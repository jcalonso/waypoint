package ecs

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hashicorp/waypoint-plugin-sdk/framework/resource"
	sdk "github.com/hashicorp/waypoint-plugin-sdk/proto/gen"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/route53"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/waypoint-plugin-sdk/component"
	"github.com/hashicorp/waypoint-plugin-sdk/docs"
	"github.com/hashicorp/waypoint-plugin-sdk/terminal"
	"github.com/hashicorp/waypoint/builtin/aws/utils"
	"github.com/hashicorp/waypoint/builtin/docker"
)

const (
	executionRolePolicyArn        = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
	awsCreateRetries              = 30
	awsCreateRetryIntervalSeconds = 2
	defaultServicePort            = 3000
)

type Platform struct {
	config Config
}

// Config implements Configurable
func (p *Platform) Config() (interface{}, error) {
	return &p.config, nil
}

// ConfigSet is called after a configuration has been decoded
// we can use this to validate the config
func (p *Platform) ConfigSet(config interface{}) error {
	c, ok := config.(*Config)
	if !ok {
		// this should never happen
		return fmt.Errorf("invalid configuration, expected *cloudrun.Config, got %T", config)
	}

	if c.ALB != nil {
		alb := c.ALB
		err := utils.Error(validation.ValidateStruct(alb,
			validation.Field(&alb.CertificateId,
				validation.Empty.When(alb.ListenerARN != "").Error("certificate can not be used with listener_arn"),
			),
			validation.Field(&alb.ZoneId,
				validation.Empty.When(alb.ListenerARN != ""),
				validation.Required.When(alb.FQDN != ""),
			),
			validation.Field(&alb.FQDN,
				validation.Empty.When(alb.ListenerARN != ""),
				validation.Required.When(alb.ZoneId != "").Error("fqdn only valid with zone_id"),
			),
			validation.Field(&alb.InternalScheme,
				validation.Nil.When(alb.ListenerARN != "").Error("internal can not be used with listener_arn"),
			),
			validation.Field(&alb.ListenerARN,
				validation.Empty.When(alb.CertificateId != "" || alb.ZoneId != "" || alb.FQDN != "").Error("listener_arn can not be used with other options"),
			),
		))
		if err != nil {
			return err
		}
	}

	err := utils.Error(validation.ValidateStruct(c,
		validation.Field(&c.Memory, validation.Required, validation.Min(4)),
		validation.Field(&c.MemoryReservation, validation.Min(4), validation.Max(c.Memory)),
	))
	if err != nil {
		return err
	}

	for _, cc := range c.ContainersConfig {
		err := utils.Error(validation.ValidateStruct(cc,
			validation.Field(&cc.Memory, validation.Required, validation.Min(4)),
			validation.Field(&cc.MemoryReservation, validation.Min(4), validation.Max(cc.Memory)),
		))
		if err != nil {
			return err
		}
	}

	return nil
}

// DeployFunc implements component.Platform
func (p *Platform) DeployFunc() interface{} {
	return p.Deploy
}

// DestroyFunc implements component.Destroyer
func (p *Platform) DestroyFunc() interface{} {
	return p.Destroy
}

// ValidateAuthFunc implements component.Authenticator
func (p *Platform) ValidateAuthFunc() interface{} {
	return p.ValidateAuth
}

// AuthFunc implements component.Authenticator
func (p *Platform) AuthFunc() interface{} {
	return p.Auth
}

func (p *Platform) Auth() error {
	return nil
}

func (p *Platform) ValidateAuth() error {
	return nil
}

// DefaultReleaserFunc implements component.PlatformReleaser
func (p *Platform) DefaultReleaserFunc() interface{} {
	// TODO(izaak): Switch this to the ALB releaser if possible?
	return func() *Releaser { return &Releaser{p: p} }
}

func (p *Platform) resourceManager(log hclog.Logger, dcr *component.DeclaredResourcesResp) *resource.Manager {
	return resource.NewManager(
		resource.WithLogger(log.Named("resource_manager")),
		resource.WithValueProvider(p.getSession),
		resource.WithDeclaredResourcesResp(dcr),
		resource.WithResource(resource.NewResource(
			resource.WithName("cluster"),
			resource.WithPlatform(platformName),
			resource.WithState(&Resource_Cluster{}),
			resource.WithCreate(p.resourceClusterCreate),
			// TODO: implement destroy when we have better support for app-scoped resources
			resource.WithStatus(p.resourceClusterStatus),
			resource.WithCategoryDisplayHint(sdk.ResourceCategoryDisplayHint_OTHER),
		)),
		resource.WithResource(resource.NewResource(
			resource.WithName("execution role"),
			resource.WithPlatform(platformName),
			resource.WithState(&Resource_ExecutionRole{}),
			resource.WithCreate(p.resourceExecutionRoleCreate),
			// TODO: implement destroy when we have better support for app-scoped resources
			// TODO: implement status when we have a plan to not hit rate limits
			resource.WithCategoryDisplayHint(sdk.ResourceCategoryDisplayHint_POLICY),
		)),
		resource.WithResource(resource.NewResource(
			resource.WithName("task role"),
			resource.WithPlatform(platformName),
			resource.WithState(&Resource_TaskRole{}),
			resource.WithCreate(p.resourceTaskRoleDiscover),
			// We never create the task role, and therefore never destroy it
			// TODO: implement status when we have a plan to not hit rate limits
			resource.WithCategoryDisplayHint(sdk.ResourceCategoryDisplayHint_POLICY),
		)),
		resource.WithResource(resource.NewResource(
			resource.WithName("security groups"),
			resource.WithPlatform(platformName),
			resource.WithState(&Resource_SecurityGroups{}),
			resource.WithCreate(p.resourceSecurityGroupsCreate),
			// TODO: implement destroy when we have better support for app-scoped resources
			// TODO: implement status when we have a plan to not hit rate limits
			resource.WithCategoryDisplayHint(sdk.ResourceCategoryDisplayHint_POLICY),
		)),
		resource.WithResource(resource.NewResource(
			resource.WithName("log group"),
			resource.WithPlatform(platformName),
			resource.WithState(&Resource_LogGroup{}),
			resource.WithCreate(p.resourceLogGroupCreate),
			// TODO: implement destroy when we have better support for app-scoped resources
			// TODO: implement status when we have a plan to not hit rate limits
			resource.WithCategoryDisplayHint(sdk.ResourceCategoryDisplayHint_OTHER),
		)),
		resource.WithResource(resource.NewResource(
			resource.WithName("subnets"),
			resource.WithPlatform(platformName),
			resource.WithState(&Resource_Subnets{}),
			resource.WithCreate(p.resourceSubnetsDiscover),
			// We never create subnets, and therefore should never destroy them
			// TODO: implement status when we have a plan to not hit rate limits
			resource.WithCategoryDisplayHint(sdk.ResourceCategoryDisplayHint_OTHER),
		)),
		resource.WithResource(resource.NewResource(
			resource.WithName("target group"),
			resource.WithPlatform(platformName),
			resource.WithState(&Resource_TargetGroup{}),
			resource.WithCreate(p.resourceTargetGroupCreate),
			// TODO(izaak): destroy
			// TODO: implement status when we have a plan to not hit rate limits
			resource.WithCategoryDisplayHint(sdk.ResourceCategoryDisplayHint_OTHER),
		)),
		resource.WithResource(resource.NewResource(
			resource.WithName("service"),
			resource.WithPlatform(platformName),
			resource.WithState(&Resource_Cluster{}),
			resource.WithCreate(p.resourceServiceCreate),
			// TODO(izaak) implement
			//resource.WithDestroy(p.resourceServiceDestroy),
			//resource.WithStatus(p.resourceServiceStatus),
			resource.WithCategoryDisplayHint(sdk.ResourceCategoryDisplayHint_INSTANCE_MANAGER),
		)),
	)
}

// DeploymentId is a unique ID to be consistently used throughout our deployment
type DeploymentId string

// VpcID is the id of the AWS VPC this ecs deployment will live in
type VpcID string

func (p *Platform) resourceTargetGroupCreate(
	ctx context.Context,
	sg terminal.StepGroup,
	sess *session.Session,
	deploymentId DeploymentId,
	vpcId VpcID,
	state *Resource_TargetGroup,
) error {
	s := sg.Add("Creating target group")
	defer s.Abort()

	elbsrv := elbv2.New(sess)

	// Use our common deployment ID as the target group name
	targetGroupName := string(deploymentId)

	if p.config.ServicePort != 0 {
		s.Update("Using configured service port %d", p.config.ServicePort)
		state.Port = p.config.ServicePort
	} else {
		s.Update("Using the default service port %d", defaultServicePort)
		state.Port = int64(defaultServicePort)
	}

	vpcIdStr := string(vpcId)
	ctg, err := elbsrv.CreateTargetGroupWithContext(ctx, &elbv2.CreateTargetGroupInput{
		HealthCheckEnabled: aws.Bool(true),
		Name:               &targetGroupName,
		Port:               &state.Port,
		Protocol:           aws.String("HTTP"),
		TargetType:         aws.String("ip"),
		VpcId:              &vpcIdStr,
	})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to create target group: %s", err)
	}
	if len(ctg.TargetGroups) == 0 {
		return status.Errorf(codes.FailedPrecondition, "failed to create target group")
	}

	state.Name = *ctg.TargetGroups[0].TargetGroupName
	state.Arn = *ctg.TargetGroups[0].TargetGroupArn

	s.Status("Successfully created target group")

	s.Done()
	return nil
}

func (p *Platform) resourceSubnetsDiscover(
	ctx context.Context,
	sg terminal.StepGroup,
	sess *session.Session,
	state *Resource_Subnets,
) (VpcId, error) {
	s := sg.Add("Discovering which subnets to use")
	defer s.Abort()

	var subnets []*string
	var vpcId string
	var err error
	if len(p.config.Subnets) == 0 {
		s.Update("Using default subnets for Service networking")
		subnets, vpcId, err = defaultSubnets(ctx, sess)
		if err != nil {
			return "", status.Errorf(codes.FailedPrecondition, "failed to determine default subnets: %s", err)
		}
	} else {
		s.Update("Using defined subnets for Service networking")
		subnets = make([]*string, len(p.config.Subnets))
		for i := range p.config.Subnets {
			subnets[i] = &p.config.Subnets[i]
		}

		// We need to determine the vpc id via the API if we were given subnet IDs.
		ec2srv := ec2.New(sess)

		subnetInfo, err := ec2srv.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{
			SubnetIds: subnets,
		})
		if err != nil {
			return "", status.Errorf(codes.FailedPrecondition, "failed to describe subnets %q: %s", strings.Join(p.config.Subnets, ", "), err)
		}
		if len(subnetInfo.Subnets) == 0 {
			return "", status.Errorf(codes.FailedPrecondition, "failed to find any subnets with IDs %q", strings.Join(p.config.Subnets, ", "))
		}

		vpcId = *subnetInfo.Subnets[0].VpcId
	}
	for _, subnet := range subnets {
		state.Subnets = append(state.Subnets, &Resource_Subnets_Subnet{Id: *subnet})
	}
	return VpcId(vpcId), nil
}

func (p *Platform) resourceSecurityGroupsCreate(
	ctx context.Context,
	sg terminal.StepGroup,
	sess *session.Session,
	src *component.Source,
	vpcId VpcID,
	state *Resource_SecurityGroups,
) error {
	s := sg.Add("Initiating security group creation...")
	defer s.Abort()

	if p.config.SecurityGroupIDs != nil {
		s.Update("Using specified security group IDs")
		for _, sgId := range p.config.SecurityGroupIDs {
			state.SecurityGroups = append(state.SecurityGroups, &Resource_SecurityGroups_SecurityGroup{Id: *sgId})
		}
		s.Done()
		return nil
	}

	name := fmt.Sprintf("%s-inbound", src.App)
	// TODO(izaak): think about discovering non-inbound security groups from the old logic?
	s.Update("No security groups specified - checking for existing security group named %q", name)

	ec2srv := ec2.New(sess)
	dsg, err := ec2srv.DescribeSecurityGroupsWithContext(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []*string{aws.String(name)},
			},
		},
	})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to describe security groups named %q: %s", name, err)
	}

	var groupId *string
	if len(dsg.SecurityGroups) != 0 {
		groupId = dsg.SecurityGroups[0].GroupId
		s.Update("Using existing security group: %s", name)

		// NOTE(izaak): We're verifying that the sg exists, but not that it has the correct group ingress input.
		// It's possible that we failed on that step earlier. We could call AuthorizeSecurityGroupIngress every time,
		// but we're trying to minimize per-deployment aws api invocations for to stay under rate limits.

		state.SecurityGroups = append(state.SecurityGroups, &Resource_SecurityGroups_SecurityGroup{Id: *groupId})
		s.Done()
		return nil
	}

	s.Update("Creating security group: %s", name)

	vpcIdStr := string(vpcId)
	out, err := ec2srv.CreateSecurityGroupWithContext(ctx, &ec2.CreateSecurityGroupInput{
		Description: aws.String("created by waypoint"),
		GroupName:   aws.String(name),
		VpcId:       &vpcIdStr,
	})
	if err != nil {
		return err
	}

	groupId = out.GroupId
	s.Update("Created security group: %s", name)

	state.SecurityGroups = append(state.SecurityGroups, &Resource_SecurityGroups_SecurityGroup{Id: *groupId})

	s.Done()
	return nil
}

type VpcId string
type SubnetIds []string

// todo: comment
func (p *Platform) resourceServiceCreate(
	ctx context.Context,
	sg terminal.StepGroup,
	log hclog.Logger,
	sess *session.Session,
	src *component.Source,
	img *docker.Image,
	deployConfig *component.DeploymentConfig,
	deploymentId DeploymentId,

	// Outputs of other resource creation processes
	state *Resource_Service,
	executionRole *Resource_ExecutionRole,
	taskRole *Resource_TaskRole,
	logGroup *Resource_LogGroup,
	cluster *Resource_Cluster,
	targetGroup *Resource_TargetGroup,
	subnets *Resource_Subnets,
	securityGroups *Resource_SecurityGroups,
) error {
	s := sg.Add("Initiating ecs service creation...")
	defer s.Abort()

	// Build environment variables
	env := []*ecs.KeyValuePair{
		{
			Name:  aws.String("PORT"),
			Value: aws.String(fmt.Sprint(p.config.ServicePort)),
		},
	}

	for k, v := range p.config.Environment {
		env = append(env, &ecs.KeyValuePair{
			Name:  aws.String(k),
			Value: aws.String(v),
		})
	}

	for k, v := range deployConfig.Env() {
		env = append(env, &ecs.KeyValuePair{
			Name:  aws.String(k),
			Value: aws.String(v),
		})
	}

	// Build secrets
	var secrets []*ecs.Secret
	for k, v := range p.config.Secrets {
		secrets = append(secrets, &ecs.Secret{
			Name:      aws.String(k),
			ValueFrom: aws.String(v),
		})
	}

	// Build logging options
	defaultStreamPrefix := fmt.Sprintf("waypoint-%d", time.Now().Nanosecond())

	logOptions := buildLoggingOptions(
		p.config.Logging,
		p.config.Region,
		logGroup.Name,
		defaultStreamPrefix,
	)

	// Define app container
	def := ecs.ContainerDefinition{
		Essential: aws.Bool(true),
		Name:      aws.String(src.App),
		Image:     aws.String(img.Name()),
		PortMappings: []*ecs.PortMapping{
			{
				ContainerPort: aws.Int64(p.config.ServicePort),
			},
		},
		Environment:       env,
		Memory:            utils.OptionalInt64(int64(p.config.Memory)),
		MemoryReservation: utils.OptionalInt64(int64(p.config.MemoryReservation)),
		Secrets:           secrets,
		LogConfiguration: &ecs.LogConfiguration{
			LogDriver: aws.String("awslogs"),
			Options:   logOptions,
		},
	}

	// Define sidecar containers
	var additionalContainers []*ecs.ContainerDefinition
	for _, container := range p.config.ContainersConfig {
		var secrets []*ecs.Secret
		for k, v := range container.Secrets {
			secrets = append(secrets, &ecs.Secret{
				Name:      aws.String(k),
				ValueFrom: aws.String(v),
			})
		}

		var env []*ecs.KeyValuePair
		for k, v := range container.Environment {
			env = append(env, &ecs.KeyValuePair{
				Name:  aws.String(k),
				Value: aws.String(v),
			})
		}

		c := &ecs.ContainerDefinition{
			Essential: aws.Bool(false),
			Name:      aws.String(container.Name),
			Image:     aws.String(container.Image),
			PortMappings: []*ecs.PortMapping{
				{
					ContainerPort: aws.Int64(int64(container.ContainerPort)),
					HostPort:      aws.Int64(int64(container.HostPort)),
					Protocol:      aws.String(container.Protocol),
				},
			},
			HealthCheck: &ecs.HealthCheck{
				Command:     aws.StringSlice(container.HealthCheck.Command),
				Interval:    aws.Int64(container.HealthCheck.Interval),
				Timeout:     aws.Int64(container.HealthCheck.Timeout),
				Retries:     aws.Int64(container.HealthCheck.Retries),
				StartPeriod: aws.Int64(container.HealthCheck.StartPeriod),
			},
			Secrets:           secrets,
			Environment:       env,
			Memory:            utils.OptionalInt64(int64(container.Memory)),
			MemoryReservation: utils.OptionalInt64(int64(container.MemoryReservation)),
		}

		additionalContainers = append(additionalContainers, c)
	}

	containerDefinitions := append([]*ecs.ContainerDefinition{&def}, additionalContainers...)

	family := "waypoint-" + src.App
	s.Update("Registering Task definition: %s", family)

	var cpuShares int
	runtime := aws.String("FARGATE")
	if p.config.EC2Cluster {
		runtime = aws.String("EC2")
		cpuShares = p.config.CPU
	} else {
		if err := utils.ValidateEcsMemCPUPair(p.config.Memory, p.config.CPU); err != nil {
			return err
		}

		cpuValues := fargateResources[p.config.Memory]

		// at this point we know that config.CPU is either 0, or a valid value
		// for the memory given
		cpuShares = p.config.CPU
		if cpuShares == 0 {
			cpuShares = cpuValues[0]
		}
	}

	cpus := aws.String(strconv.Itoa(cpuShares))
	// on EC2 launch type, `Cpu` is an optional field, so we leave it nil if it is 0
	if p.config.EC2Cluster && cpuShares == 0 {
		cpus = nil
	}
	mems := strconv.Itoa(p.config.Memory)

	registerTaskDefinitionInput := ecs.RegisterTaskDefinitionInput{
		ContainerDefinitions: containerDefinitions,

		ExecutionRoleArn: aws.String(executionRole.Arn),
		Cpu:              cpus,
		Memory:           aws.String(mems),
		Family:           aws.String(family),

		NetworkMode:             aws.String("awsvpc"),
		RequiresCompatibilities: []*string{runtime},

		Tags: []*ecs.Tag{
			{
				Key:   aws.String("waypoint-app"),
				Value: aws.String(src.App),
			},
		},
	}

	if taskRole != nil && taskRole.Arn != "" {
		registerTaskDefinitionInput.SetTaskRoleArn(taskRole.Arn)
	}

	ecsSvc := ecs.New(sess)

	var taskOut *ecs.RegisterTaskDefinitionOutput
	var err error
	// AWS is eventually consistent so even though we probably created the resources that
	// are referenced by the task definition, it can error out if we try to reference those resources
	// too quickly. So we're forced to guard actions which reference other AWS services
	// with loops like this.

	for i := 0; i <= awsCreateRetries; i++ {
		taskOut, err = ecsSvc.RegisterTaskDefinitionWithContext(ctx, &registerTaskDefinitionInput)
		if err == nil {
			break
		}

		// if we encounter an unrecoverable error, exit now.
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "ResourceConflictException":
				break
			}
		}

		s.Update(fmt.Sprintf("Failed to register ecs task definiton. Will retry in %d seconds (up to %d more times)\nError: %s", awsCreateRetryIntervalSeconds, awsCreateRetries-i))

		// otherwise sleep and try again
		time.Sleep(awsCreateRetryIntervalSeconds * time.Second)
	}
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed registering ecs task definition: %s", err)
	}

	s.Update("Registered Task definition: %s", family)

	// Use the common deployment ID as our service name
	serviceName := string(deploymentId)

	// We have to clamp at a length of 32 because the Name field to CreateTargetGroup
	// requires that the name is 32 characters or less.
	if len(serviceName) > 32 {
		serviceName = serviceName[:32]
		log.Debug("using a shortened value for service name due to AWS's length limits", "serviceName", serviceName)
	}

	taskArn := *taskOut.TaskDefinition.TaskDefinitionArn

	count := int64(p.config.Count)
	if count == 0 {
		count = 1
	}

	securityGroupIds := make([]*string, len(securityGroups.SecurityGroups))
	for i, securityGroup := range securityGroups.SecurityGroups {
		securityGroupIds[i] = &securityGroup.Id
	}

	subnetIds := make([]*string, len(subnets.Subnets))
	for i, subnet := range subnets.Subnets {
		subnetIds[i] = &subnet.Id
	}

	netCfg := &ecs.AwsVpcConfiguration{
		Subnets:        subnetIds,
		SecurityGroups: securityGroupIds,
	}

	if !p.config.EC2Cluster {
		netCfg.AssignPublicIp = aws.String("ENABLED")
	}

	createServiceInput := &ecs.CreateServiceInput{
		Cluster:        &cluster.Name,
		DesiredCount:   aws.Int64(count),
		LaunchType:     runtime,
		ServiceName:    aws.String(serviceName),
		TaskDefinition: aws.String(taskArn),
		NetworkConfiguration: &ecs.NetworkConfiguration{
			AwsvpcConfiguration: netCfg,
		},

		// TODO(izaak): make sure it's ok to do this every time - even if no ALB is desired
		LoadBalancers: []*ecs.LoadBalancer{{
			ContainerName:  aws.String(src.App),
			ContainerPort:  aws.Int64(targetGroup.Port),
			TargetGroupArn: &targetGroup.Arn,
		}},
	}

	s.Update("Creating ECS Service (%s, cluster-name: %s)", serviceName, cluster.Name)

	// AWS is eventually consistent so even though we probably created the resources that
	// are referenced by the task definition, it can error out if we try to reference those resources
	// too quickly. So we're forced to guard actions which reference other AWS services
	// with loops like this.
	var servOut *ecs.CreateServiceOutput
	for i := 0; i <= awsCreateRetries; i++ {
		servOut, err = ecsSvc.CreateServiceWithContext(ctx, createServiceInput)
		if err == nil {
			break
		}

		// if we encounter an unrecoverable error, exit now.
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "AccessDeniedException", "UnsupportedFeatureException",
				"PlatformUnknownException",
				"PlatformTaskDefinitionIncompatibilityException":
				break
			}
		}

		s.Update(fmt.Sprintf("Failed to register ecs service. Will retry in %d seconds (up to %d more times)\nError: %s", awsCreateRetryIntervalSeconds, awsCreateRetries-i))

		// otherwise sleep and try again
		time.Sleep(awsCreateRetryIntervalSeconds * time.Second)
	}
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed registering ecs service: %s", err)
	}

	state.Name = *servOut.Service.ServiceName
	state.Arn = *servOut.Service.ServiceArn

	s.Update("Created ECS Service (%s, cluster-name: %s)", serviceName, cluster.Name)
	s.Done()
	return nil
}

// todo: comment
func (p *Platform) resourceLogGroupCreate(
	ctx context.Context,
	sg terminal.StepGroup,
	sess *session.Session,
	state *Resource_LogGroup,
) error {
	s := sg.Add("Initiating log group creation...")
	defer s.Abort()

	logGroup := p.config.LogGroup
	if logGroup == "" {
		logGroup = "waypoint-logs"
	}

	s.Update("Looking for existing log group named %s", logGroup)

	cwl := cloudwatchlogs.New(sess)
	groups, err := cwl.DescribeLogGroupsWithContext(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
		Limit:              aws.Int64(1),
		LogGroupNamePrefix: aws.String(logGroup),
	})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to describe log groups: %s", err)
	}

	if len(groups.LogGroups) == 1 {
		s.Update("Found existing log group named %s", logGroup)
		lg := groups.LogGroups[0]
		state.Name = *lg.LogGroupName
		state.Arn = *lg.Arn
	}

	s.Update("No existing log group found - creating CloudWatchLogs group to store logs in: %s", logGroup)

	_, err = cwl.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroup),
	})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed creating log group %s: %s", logGroup, err)
	}

	//NOTE(izaak): CreateLogGroup doesn't return the log group ARN.
	state.Name = logGroup

	s.Update("Created CloudWatchLogs group to store logs in: %s", logGroup)
	s.Done()
	return nil
}

// todo: comment
func (p *Platform) resourceTaskRoleDiscover(
	ctx context.Context,
	sg terminal.StepGroup,
	sess *session.Session,
	state *Resource_TaskRole,
) error {
	if p.config.TaskRoleName == "" {
		return nil
	}

	s := sg.Add("Initiating task role creation...")
	defer s.Abort()

	roleName := p.config.TaskRoleName

	s.Update("Attempting to find an existing role named %q", roleName)

	queryInput := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}

	svc := iam.New(sess)
	getOut, err := svc.GetRoleWithContext(ctx, queryInput)
	if err != nil {
		// TODO(izaak): Is this enough, or do we need status output here?
		return status.Errorf(codes.FailedPrecondition, "requested task IAM role not found: %s", roleName)
	}

	s.Update("Found existing task IAM role: %s", roleName)

	state.Name = roleName
	state.Arn = *getOut.Role.Arn
	s.Done()
	return nil
}

// todo: comment
func (p *Platform) resourceExecutionRoleCreate(
	ctx context.Context,
	sg terminal.StepGroup,
	log hclog.Logger,
	sess *session.Session,
	src *component.Source,
	state *Resource_ExecutionRole,
) error {
	s := sg.Add("Initiating execution role creation...")
	defer s.Abort()

	roleName := p.config.ExecutionRoleName

	if roleName == "" {
		roleName = "ecr-" + src.App
		state.Managed = true
	} else {
		// If the role name is defined, we're not managing this role, and shouldn't destroy it later.
		state.Managed = false
	}
	// role names have to be 64 characters or less, and the client side doesn't validate this.
	if len(roleName) > 64 {
		roleName = roleName[:64]
		log.Debug("using a shortened value for role name due to AWS's length limits", "roleName", roleName)
	}
	state.Name = roleName

	s.Update("Attempting to find an existing role named %q", roleName)

	queryInput := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}

	svc := iam.New(sess)

	getOut, err := svc.GetRoleWithContext(ctx, queryInput)
	if err == nil {
		s.Update("Found existing IAM role to use (arn: %q)", *getOut.Role.Arn)

		// NOTE(izaak): We're verifying that the role exists, but not that it has the correct policy attached.
		// It's possible that we failed on that step earlier. We could call AttachRolePolicy every time, but
		// we're trying to minimize per-deployment aws api invocations for to stay under rate limits.

		state.Arn = *getOut.Role.Arn
		s.Done()
		return nil
	}
	s.Update("No existing execution role found: creating IAM role %q", roleName)

	input := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(rolePolicy),
		Path:                     aws.String("/"),
		RoleName:                 aws.String(roleName),
	}

	result, err := svc.CreateRoleWithContext(ctx, input)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed creating execution role %q: %s", roleName, err)
	}
	state.Arn = *result.Role.Arn

	s.Update("Attaching default execution policy to role %q", roleName)
	aInput := &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String(executionRolePolicyArn),
	}

	_, err = svc.AttachRolePolicyWithContext(ctx, aInput)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "failed to attach policy %q to role %q: %s", executionRolePolicyArn, roleName, err)
	}

	s.Update("Finished creating execution IAM role: %s", roleName)
	s.Done()
	return nil
}

// TODO: comment
func (p *Platform) resourceClusterCreate(
	ctx context.Context,
	sg terminal.StepGroup,
	log hclog.Logger,
	sess *session.Session,
	state *Resource_Cluster,
) error {
	s := sg.Add("Initiating cluster creation...")
	defer s.Abort()

	cluster := p.config.Cluster
	if cluster == "" {
		cluster = "waypoint"
	}
	state.Name = cluster

	s.Update("Attempting to find existing cluster named %q", cluster)

	ecsSvc := ecs.New(sess)
	desc, err := ecsSvc.DescribeClustersWithContext(ctx, &ecs.DescribeClustersInput{
		Clusters: []*string{aws.String(cluster)},
	})
	if err != nil {
		return err
	}

	for _, c := range desc.Clusters {
		if *c.ClusterName == cluster {
			if *c.Status == "PROVISIONING" {
				s.Update("Existing ecs cluster %q is still provisioning - try again later.", cluster)
				// TODO: This case should be rare, but it might be nice to automatically wait here and poll until the cluster is ready.
			} else if *c.Status == "ACTIVE" {
				s.Update("Found existing ECS cluster: %s", cluster)
				if c.ClusterArn != nil {
					state.Arn = *c.ClusterArn
				}
				s.Done()
				return nil
			} else {
				// Warn if we encounter waypoint clusters in other odd states (i.e. DEPROVISIONING, FAILED, etc.)
				// I think it's ok to try to create a new cluster if one exists in a non-active non-provisioning state
				log.Warn("Ignoring cluster named %q in state %q", cluster, *c.Status)
			}
		}
	}

	if p.config.EC2Cluster {
		return fmt.Errorf("EC2 clusters can not be automatically created")
	}

	s.Update("No existing cluster found - creating new ECS cluster: %s", cluster)

	c, err := ecsSvc.CreateClusterWithContext(ctx, &ecs.CreateClusterInput{
		ClusterName: aws.String(cluster),
	})

	if err != nil {
		return err
	}

	if c.Cluster != nil && c.Cluster.ClusterArn != nil {
		state.Arn = *c.Cluster.ClusterArn
	}

	// TODO(izaak): Do we need to block here until the cluster is in ACTIVE state?

	s.Update("Created new ECS cluster: %s", cluster)
	s.Done()
	return nil
}

func (p *Platform) resourceClusterStatus(
	ctx context.Context,
	sg terminal.StepGroup,
	sess *session.Session,
	state *Resource_Cluster,
	sr *resource.StatusResponse,
) error {
	s := sg.Add("Checking status of the ecs cluster %q...", state.Name)
	defer s.Abort()

	ecsSvc := ecs.New(sess)
	desc, err := ecsSvc.DescribeClustersWithContext(ctx, &ecs.DescribeClustersInput{
		Clusters: []*string{aws.String(state.Name)},
	})
	if err != nil {
		return err
	}

	clusterResource := sdk.StatusReport_Resource{
		Name: state.Name,
	}

	sr.Resources = append(sr.Resources, &clusterResource)

	for _, c := range desc.Clusters {
		if *c.ClusterName == state.Name {
			s.Update("Found existing ECS cluster: %s", state.Name)
			clusterResource.Id = *c.ClusterArn
			switch *c.Status {
			case "ACTIVE":
				clusterResource.Health = sdk.StatusReport_READY
			case "PROVISIONING":
				clusterResource.Health = sdk.StatusReport_ALIVE
			case "DEPROVISIONING", "FAILED", "INACTIVE":
				clusterResource.Health = sdk.StatusReport_DOWN
			default:
				clusterResource.Health = sdk.StatusReport_UNKNOWN
			}
			clusterResource.HealthMessage = *c.Status

			stateJson, err := json.Marshal(c)
			if err != nil {
				return status.Errorf(codes.FailedPrecondition, "failed to marshal ecs cluster state json: %s", err)
			}
			clusterResource.StateJson = string(stateJson)
			return nil
		}
	}

	// Failed to find ECS cluster
	clusterResource.Health = sdk.StatusReport_MISSING
	clusterResource.HealthMessage = fmt.Sprintf("No cluster named %q found (expected arn %q)", state.Name, state.Arn)

	s.Update("Done checking ecs cluster status")
	s.Done()
	return nil
}

// getSession is a value provider for resource manager and provides a client
// for use by resources to interact with AWS
func (p *Platform) getSession(log hclog.Logger) (*session.Session, error) {
	sess, err := utils.GetSession(&utils.SessionConfig{
		Region: p.config.Region,
		Logger: log,
	})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("failed to create aws session: %s", err))
	}
	return sess, nil
}

func (p *Platform) Deploy(
	ctx context.Context,
	log hclog.Logger,
	src *component.Source,
	img *docker.Image,
	deployConfig *component.DeploymentConfig,
	ui terminal.UI,
	dcr *component.DeclaredResourcesResp,
) (*Deployment, error) {

	var result Deployment

	// We'll update the user in real time
	sg := ui.StepGroup()
	defer sg.Wait()

	// Generate a common deployment ID to use in the resources we create.
	// TODO: should include the sequence ID
	ulid, err := component.Id()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "failed to generate a ULID: %s", err)
	}
	deploymentId := DeploymentId(fmt.Sprintf("%s-%s", src.App, ulid))

	// Create our resource manager and create
	rm := p.resourceManager(log, dcr)
	if err := rm.CreateAll(
		ctx, log, sg, ui, deploymentId,
		src, img, deployConfig, &result,
	); err != nil {
		return nil, err
	}

	return &result, nil

	// TODO: delete below

	//var (
	//	dep *Deployment
	//
	//	executionRole, taskRole, cluster, logGroup string
	//
	//	//err error
	//)
	//
	//if p.config.ALB != nil {
	//	if p.config.ALB.ListenerARN != "" {
	//		if p.config.ALB.ZoneId != "" || p.config.ALB.FQDN != "" {
	//			return nil, fmt.Errorf("When using an existing listener, Route53 setup is not available")
	//		}
	//
	//		if p.config.ALB.CertificateId != "" {
	//			return nil, fmt.Errorf("When using an existing listener, certification configuration is not available")
	//		}
	//	}
	//}
	//
	//if p.config.ServicePort == 0 {
	//	p.config.ServicePort = 3000
	//}
	//
	//lf := &Lifecycle{
	//	Init: func(s LifecycleStatus) error {
	//		sess, err = utils.GetSession(&utils.SessionConfig{
	//			Region: p.config.Region,
	//			Logger: log,
	//		})
	//		if err != nil {
	//			return err
	//		}
	//		cluster, err = p.SetupCluster(ctx, s, sess)
	//		if err != nil {
	//			return err
	//		}
	//
	//		executionRole, err = p.SetupExecutionRole(ctx, s, log, sess, src)
	//		if err != nil {
	//			return err
	//		}
	//
	//		if p.config.TaskRoleName != "" {
	//			taskRole, err = p.SetupTaskRole(ctx, s, log, sess, src)
	//			if err != nil {
	//				return err
	//			}
	//		}
	//
	//		logGroup, err = p.SetupLogs(ctx, s, log, sess)
	//		if err != nil {
	//			return err
	//		}
	//
	//		return nil
	//	},
	//
	//	Run: func(s LifecycleStatus) error {
	//		dep, err = p.Launch(ctx, s, log, ui, sess, src, img, deployConfig, executionRole, taskRole, cluster, logGroup)
	//		return err
	//	},
	//
	//	Cleanup: func(s LifecycleStatus) error { return nil },
	//}
	//
	//if err := lf.Execute(log, ui); err != nil {
	//	return nil, err
	//}
	//
	//return dep, nil
}

func defaultSubnets(ctx context.Context, sess *session.Session) (names []*string, vpcId string, err error) {
	svc := ec2.New(sess)

	desc, err := svc.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("default-for-az"),
				Values: []*string{aws.String("true")},
			},
		},
	})
	if err != nil {
		return nil, "", err
	}

	var subnets []*string

	for _, subnet := range desc.Subnets {
		subnets = append(subnets, subnet.SubnetId)
	}

	// Return tye vpc id if possible
	if len(desc.Subnets) != 0 && desc.Subnets[0].VpcId != nil {
		return subnets, *desc.Subnets[0].VpcId, nil
	}

	return subnets, "", nil
}

// TODO(izaak): delete
type Lifecycle struct {
	Init    func(LifecycleStatus) error
	Run     func(LifecycleStatus) error
	Cleanup func(LifecycleStatus) error
}

type lStatus struct {
	ui   terminal.UI
	sg   terminal.StepGroup
	step terminal.Step
}

func (l *lStatus) Status(str string, args ...interface{}) {
	if l.sg == nil {
		l.sg = l.ui.StepGroup()
	}

	if l.step != nil {
		l.step.Done()
		l.step = nil
	}

	l.step = l.sg.Add(str, args...)
}

func (l *lStatus) Update(str string, args ...interface{}) {
	if l.sg == nil {
		l.sg = l.ui.StepGroup()
	}

	if l.step != nil {
		l.step.Update(str, args...)
	} else {
		l.step = l.sg.Add(str, args)
	}
}

func (l *lStatus) Error(str string, args ...interface{}) {
	if l.sg == nil {
		l.sg = l.ui.StepGroup()
	}

	if l.step != nil {
		l.step.Update(str, args...)
		l.step.Abort()
	} else {
		l.step = l.sg.Add(str, args)
		l.step.Abort()
	}

	l.step = nil
}

func (l *lStatus) Abort() error {
	if l.step != nil {
		l.step.Abort()
		l.step = nil
	}

	if l.sg != nil {
		l.sg.Wait()
		l.sg = nil
	}

	return nil
}

func (l *lStatus) Close() error {
	if l.step != nil {
		l.step.Done()
		l.step = nil
	}

	if l.sg != nil {
		l.sg.Wait()
		l.sg = nil
	}

	return nil
}

func (lf *Lifecycle) Execute(L hclog.Logger, ui terminal.UI) error {
	var l lStatus
	l.ui = ui

	defer l.Close()

	if lf.Init != nil {
		L.Debug("lifecycle init")

		err := lf.Init(&l)
		if err != nil {
			l.Abort()
			return err
		}

	}

	L.Debug("lifecycle run")
	err := lf.Run(&l)
	if err != nil {
		l.Abort()
		return err
	}

	if lf.Cleanup != nil {
		L.Debug("lifecycle cleanup")

		err = lf.Cleanup(&l)
		if err != nil {
			l.Abort()
			return err
		}
	}

	return nil
}

type LifecycleStatus interface {
	Status(str string, args ...interface{})
	Update(str string, args ...interface{})
	Error(str string, args ...interface{})
}

//func (p *Platform) SetupCluster(ctx context.Context, s LifecycleStatus, sess *session.Session) (string, error) {
//	ecsSvc := ecs.New(sess)
//
//	cluster := p.config.Cluster
//	if cluster == "" {
//		cluster = "waypoint"
//	}
//
//	desc, err := ecsSvc.DescribeClusters(&ecs.DescribeClustersInput{
//		Clusters: []*string{aws.String(cluster)},
//	})
//	if err != nil {
//		return "", err
//	}
//
//	for _, c := range desc.Clusters {
//		if *c.ClusterName == cluster && strings.ToLower(*c.Status) == "active" {
//			s.Status("Found existing ECS cluster: %s", cluster)
//			return cluster, nil
//		}
//	}
//
//	if p.config.EC2Cluster {
//		return "", fmt.Errorf("EC2 clusters can not be automatically created")
//	}
//
//	s.Status("Creating new ECS cluster: %s", cluster)
//
//	_, err = ecsSvc.CreateCluster(&ecs.CreateClusterInput{
//		ClusterName: aws.String(cluster),
//	})
//
//	if err != nil {
//		return "", err
//	}
//
//	s.Update("Created new ECS cluster: %s", cluster)
//	return cluster, nil
//}

const rolePolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
		  "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}`

var fargateResources = map[int][]int{
	512:  {256},
	1024: {256, 512},
	2048: {256, 512, 1024},
	3072: {512, 1024},
	4096: {512, 1024},
	5120: {1024},
	6144: {1024},
	7168: {1024},
	8192: {1024},
}

func init() {
	for i := 4096; i < 16384; i += 1024 {
		fargateResources[i] = append(fargateResources[i], 2048)
	}

	for i := 8192; i <= 30720; i += 1024 {
		fargateResources[i] = append(fargateResources[i], 4096)
	}
}

func (p *Platform) SetupTaskRole(ctx context.Context, s LifecycleStatus, L hclog.Logger, sess *session.Session, app *component.Source) (string, error) {
	svc := iam.New(sess)

	roleName := p.config.TaskRoleName

	L.Debug("attempting to retrieve existing role", "role-name", roleName)

	queryInput := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}

	getOut, err := svc.GetRole(queryInput)
	if err != nil {
		s.Status("IAM role not found: %s", roleName)
		return "", err
	}

	s.Status("Found task IAM role to use: %s", roleName)
	return *getOut.Role.Arn, nil
}

func (p *Platform) SetupExecutionRole(ctx context.Context, s LifecycleStatus, L hclog.Logger, sess *session.Session, app *component.Source) (string, error) {
	svc := iam.New(sess)

	roleName := p.config.ExecutionRoleName

	if roleName == "" {
		roleName = "ecr-" + app.App
	}

	// role names have to be 64 characters or less, and the client side doesn't validate this.
	if len(roleName) > 64 {
		roleName = roleName[:64]
		L.Debug("using a shortened value for role name due to AWS's length limits", "roleName", roleName)
	}

	// p.updateStatus("setting up IAM role")
	L.Debug("attempting to retrieve existing role", "role-name", roleName)

	queryInput := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}

	getOut, err := svc.GetRole(queryInput)
	if err == nil {
		s.Status("Found existing IAM role to use: %s", roleName)
		return *getOut.Role.Arn, nil
	}

	L.Debug("creating new role")
	s.Status("Creating IAM role: %s", roleName)

	input := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(rolePolicy),
		Path:                     aws.String("/"),
		RoleName:                 aws.String(roleName),
	}

	result, err := svc.CreateRole(input)
	if err != nil {
		return "", err
	}

	roleArn := *result.Role.Arn

	L.Debug("created new role", "arn", roleArn)

	aInput := &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"),
	}

	_, err = svc.AttachRolePolicy(aInput)
	if err != nil {
		return "", err
	}

	L.Debug("attached execution role policy")

	s.Update("Created IAM role: %s", roleName)
	return roleArn, nil
}

func (p *Platform) SetupLogs(ctx context.Context, s LifecycleStatus, L hclog.Logger, sess *session.Session) (string, error) {
	// e.updateStatus("setting up CloudWatchLogs")

	logGroup := p.config.LogGroup
	if logGroup == "" {
		logGroup = "waypoint-logs"
	}

	cwl := cloudwatchlogs.New(sess)
	groups, err := cwl.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
		Limit:              aws.Int64(1),
		LogGroupNamePrefix: aws.String(logGroup),
	})
	if err != nil {
		return "", err
	}

	if len(groups.LogGroups) == 0 {
		s.Status("Creating CloudWatchLogs group to store logs in: %s", logGroup)

		L.Debug("creating log group", "group", logGroup)
		_, err = cwl.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
			LogGroupName: aws.String(logGroup),
		})
		if err != nil {
			return "", err
		}

		s.Update("Created CloudWatchLogs group to store logs in: %s", logGroup)
	}

	return logGroup, nil
}

func createSG(
	ctx context.Context,
	s LifecycleStatus,
	sess *session.Session,
	name string,
	vpcId *string,
	ports ...int,
) (*string, error) {
	ec2srv := ec2.New(sess)

	dsg, err := ec2srv.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []*string{aws.String(name)},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	var groupId *string

	if len(dsg.SecurityGroups) != 0 {
		groupId = dsg.SecurityGroups[0].GroupId
		s.Status("Using existing security group: %s", name)
	} else {
		s.Status("Creating security group: %s", name)
		out, err := ec2srv.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
			Description: aws.String("created by waypoint"),
			GroupName:   aws.String(name),
			VpcId:       vpcId,
		})
		if err != nil {
			return nil, err
		}

		groupId = out.GroupId
		s.Update("Created security group: %s", name)
	}

	s.Update("Authorizing ports to security group")
	for _, port := range ports {
		_, err = ec2srv.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
			CidrIp:     aws.String("0.0.0.0/0"),
			FromPort:   aws.Int64(int64(port)),
			ToPort:     aws.Int64(int64(port)),
			GroupId:    groupId,
			IpProtocol: aws.String("tcp"),
		})
	}

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidPermission.Duplicate":
				// fine, means we already added it.
			default:
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	s.Update("Configured security group: %s", name)

	return groupId, nil
}

func createALB(
	ctx context.Context,
	s LifecycleStatus,
	L hclog.Logger,
	sess *session.Session,
	app *component.Source,
	albConfig *ALBConfig,
	vpcId *string,
	serviceName *string,
	sgWebId *string,
	servicePort *int64,
	subnets []*string,
) (lbArn *string, tgArn *string, err error) {
	s.Update("Creating ALB target group")
	L.Debug("creating target group", "name", serviceName)

	elbsrv := elbv2.New(sess)
	ctg, err := elbsrv.CreateTargetGroup(&elbv2.CreateTargetGroupInput{
		HealthCheckEnabled: aws.Bool(true),
		Name:               serviceName,
		Port:               servicePort,
		Protocol:           aws.String("HTTP"),
		TargetType:         aws.String("ip"),
		VpcId:              vpcId,
	})
	if err != nil {
		return nil, nil, err
	}

	tgArn = ctg.TargetGroups[0].TargetGroupArn

	s.Update("Created ALB target group")

	// Create the load balancer OR modify the existing one to have this new target
	// group but with a weight of 0

	tgs := []*elbv2.TargetGroupTuple{
		{
			TargetGroupArn: tgArn,
			Weight:         aws.Int64(0),
		},
	}

	var (
		certs    []*elbv2.Certificate
		protocol string = "HTTP"
		port     int64  = 80
	)

	if albConfig != nil && albConfig.CertificateId != "" {
		protocol = "HTTPS"
		port = 443
		certs = append(certs, &elbv2.Certificate{
			CertificateArn: &albConfig.CertificateId,
		})
	}

	var existingListener string

	if albConfig != nil && albConfig.ListenerARN != "" {
		existingListener = albConfig.ListenerARN
	}

	var (
		lb          *elbv2.LoadBalancer
		listener    *elbv2.Listener
		newListener bool
	)

	if existingListener != "" {
		out, err := elbsrv.DescribeListeners(&elbv2.DescribeListenersInput{
			ListenerArns: []*string{aws.String(existingListener)},
		})
		if err != nil {
			return nil, nil, err
		}

		listener = out.Listeners[0]
		s.Update("Using configured ALB Listener: %s (load-balancer: %s)",
			*listener.ListenerArn, *listener.LoadBalancerArn)
	} else {
		lbName := "waypoint-ecs-" + app.App
		dlb, err := elbsrv.DescribeLoadBalancers(&elbv2.DescribeLoadBalancersInput{
			Names: []*string{&lbName},
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case elbv2.ErrCodeLoadBalancerNotFoundException:
					// fine, means we'll create it.
				default:
					return nil, nil, err
				}
			} else {
				return nil, nil, err
			}
		}

		if dlb != nil && len(dlb.LoadBalancers) > 0 {
			lb = dlb.LoadBalancers[0]
			s.Update("Using existing ALB %s (%s, dns-name: %s)",
				lbName, *lb.LoadBalancerArn, *lb.DNSName)
		} else {
			s.Update("Creating new ALB: %s", lbName)

			scheme := elbv2.LoadBalancerSchemeEnumInternetFacing

			if albConfig != nil && albConfig.InternalScheme != nil && *albConfig.InternalScheme {
				scheme = elbv2.LoadBalancerSchemeEnumInternal
			}

			clb, err := elbsrv.CreateLoadBalancer(&elbv2.CreateLoadBalancerInput{
				Name:           aws.String(lbName),
				Subnets:        subnets,
				SecurityGroups: []*string{sgWebId},
				Scheme:         &scheme,
			})
			if err != nil {
				return nil, nil, err
			}

			lb = clb.LoadBalancers[0]

			s.Update("Created new ALB: %s (dns-name: %s)", lbName, *lb.DNSName)
		}

		listeners, err := elbsrv.DescribeListeners(&elbv2.DescribeListenersInput{
			LoadBalancerArn: lb.LoadBalancerArn,
		})
		if err != nil {
			return nil, nil, err
		}

		if len(listeners.Listeners) > 0 {
			listener = listeners.Listeners[0]
			s.Update("Using existing ALB Listener")
		} else {
			s.Update("Creating new ALB Listener")

			L.Info("load-balancer defined", "dns-name", *lb.DNSName)

			tgs[0].Weight = aws.Int64(100)
			lo, err := elbsrv.CreateListener(&elbv2.CreateListenerInput{
				LoadBalancerArn: lb.LoadBalancerArn,
				Port:            aws.Int64(port),
				Protocol:        aws.String(protocol),
				Certificates:    certs,
				DefaultActions: []*elbv2.Action{
					{
						ForwardConfig: &elbv2.ForwardActionConfig{
							TargetGroups: tgs,
						},
						Type: aws.String("forward"),
					},
				},
			})
			if err != nil {
				return nil, nil, err
			}

			newListener = true
			listener = lo.Listeners[0]

			s.Update("Created new ALB Listener")
		}
	}

	if !newListener {
		def := listener.DefaultActions

		if len(def) > 0 && def[0].ForwardConfig != nil {
			for _, tg := range def[0].ForwardConfig.TargetGroups {
				if *tg.Weight > 0 {
					tgs = append(tgs, tg)
					L.Debug("previous target group", "arn", *tg.TargetGroupArn)
				}
			}
		}

		s.Update("Modifying ALB Listener to introduce target group")

		_, err = elbsrv.ModifyListener(&elbv2.ModifyListenerInput{
			ListenerArn:  listener.ListenerArn,
			Port:         aws.Int64(port),
			Protocol:     aws.String(protocol),
			Certificates: certs,
			DefaultActions: []*elbv2.Action{
				{
					ForwardConfig: &elbv2.ForwardActionConfig{
						TargetGroups: tgs,
					},
					Type: aws.String("forward"),
				},
			},
		})
		if err != nil {
			return nil, nil, err
		}

		s.Update("Modified ALB Listener to introduce target group")
	}

	if albConfig != nil && albConfig.ZoneId != "" {
		r53 := route53.New(sess)

		records, err := r53.ListResourceRecordSets(&route53.ListResourceRecordSetsInput{
			HostedZoneId:    aws.String(albConfig.ZoneId),
			StartRecordName: aws.String(albConfig.FQDN),
			StartRecordType: aws.String(route53.RRTypeA),
			MaxItems:        aws.String("1"),
		})
		if err != nil {
			return nil, nil, err
		}

		fqdn := albConfig.FQDN

		// Add trailing period to match Route53 record name
		if fqdn[len(fqdn)-1] != '.' {
			fqdn += "."
		}

		var recordExists bool

		if len(records.ResourceRecordSets) > 0 {
			record := records.ResourceRecordSets[0]
			if aws.StringValue(record.Type) == route53.RRTypeA && aws.StringValue(record.Name) == fqdn {
				s.Status("Found existing Route53 record: %s", aws.StringValue(record.Name))
				L.Debug("found existing record, assuming it's correct")
				recordExists = true
			}
		}

		if !recordExists {
			s.Status("Creating new Route53 record: %s (zone-id: %s)",
				albConfig.FQDN, albConfig.ZoneId)

			L.Debug("creating new route53 record", "zone-id", albConfig.ZoneId)
			input := &route53.ChangeResourceRecordSetsInput{
				ChangeBatch: &route53.ChangeBatch{
					Changes: []*route53.Change{
						{
							Action: aws.String(route53.ChangeActionCreate),
							ResourceRecordSet: &route53.ResourceRecordSet{
								Name: aws.String(albConfig.FQDN),
								Type: aws.String(route53.RRTypeA),
								AliasTarget: &route53.AliasTarget{
									DNSName:              lb.DNSName,
									EvaluateTargetHealth: aws.Bool(true),
									HostedZoneId:         lb.CanonicalHostedZoneId,
								},
							},
						},
					},
					Comment: aws.String("managed by waypoint"),
				},
				HostedZoneId: aws.String(albConfig.ZoneId),
			}

			result, err := r53.ChangeResourceRecordSets(input)
			if err != nil {
				return nil, nil, err
			}
			L.Debug("record created", "change-id", *result.ChangeInfo.Id)

			s.Update("Created new Route53 record: %s (zone-id: %s)",
				albConfig.FQDN, albConfig.ZoneId)
		}
	}

	lbArn = listener.LoadBalancerArn

	return lbArn, tgArn, err
}

func buildLoggingOptions(
	lo *Logging,
	region string,
	logGroup string,
	defaultStreamPrefix string,
) map[string]*string {

	result := map[string]*string{
		"awslogs-region":        aws.String(region),
		"awslogs-group":         aws.String(logGroup),
		"awslogs-stream-prefix": aws.String(defaultStreamPrefix),
	}

	if lo != nil {
		// We receive the error `Log driver awslogs disallows options: awslogs-endpoint`
		// when setting `awslogs-endpoint`, so that is not included here of the
		// available options
		// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html
		result["awslogs-datetime-format"] = aws.String(lo.DateTimeFormat)
		result["awslogs-multiline-pattern"] = aws.String(lo.MultilinePattern)
		result["mode"] = aws.String(lo.Mode)
		result["max-buffer-size"] = aws.String(lo.MaxBufferSize)

		if lo.CreateGroup {
			result["awslogs-create-group"] = aws.String("true")
		}
		if lo.StreamPrefix != "" {
			result["awslogs-stream-prefix"] = aws.String(lo.StreamPrefix)
		}
	}

	for k, v := range result {
		if *v == "" {
			delete(result, k)
		}
	}

	return result
}

func (p *Platform) Launch(
	ctx context.Context,
	s LifecycleStatus,
	L hclog.Logger,
	ui terminal.UI,
	sess *session.Session,
	app *component.Source,
	img *docker.Image,
	deployConfig *component.DeploymentConfig,
	executionRoleArn, taskRoleArn, clusterName, logGroup string,
) (*Deployment, error) {
	id, err := component.Id()
	if err != nil {
		return nil, err
	}

	ecsSvc := ecs.New(sess)

	defaultStreamPrefix := fmt.Sprintf("waypoint-%d", time.Now().Nanosecond())

	env := []*ecs.KeyValuePair{
		{
			Name:  aws.String("PORT"),
			Value: aws.String(fmt.Sprint(p.config.ServicePort)),
		},
	}

	for k, v := range p.config.Environment {
		env = append(env, &ecs.KeyValuePair{
			Name:  aws.String(k),
			Value: aws.String(v),
		})
	}

	var secrets []*ecs.Secret
	for k, v := range p.config.Secrets {
		secrets = append(secrets, &ecs.Secret{
			Name:      aws.String(k),
			ValueFrom: aws.String(v),
		})
	}

	for k, v := range deployConfig.Env() {
		env = append(env, &ecs.KeyValuePair{
			Name:  aws.String(k),
			Value: aws.String(v),
		})
	}

	logOptions := buildLoggingOptions(
		p.config.Logging,
		p.config.Region,
		logGroup,
		defaultStreamPrefix,
	)

	def := ecs.ContainerDefinition{
		Essential: aws.Bool(true),
		Name:      aws.String(app.App),
		Image:     aws.String(img.Name()),
		PortMappings: []*ecs.PortMapping{
			{
				ContainerPort: aws.Int64(p.config.ServicePort),
			},
		},
		Environment:       env,
		Memory:            utils.OptionalInt64(int64(p.config.Memory)),
		MemoryReservation: utils.OptionalInt64(int64(p.config.MemoryReservation)),
		Secrets:           secrets,
		LogConfiguration: &ecs.LogConfiguration{
			LogDriver: aws.String("awslogs"),
			Options:   logOptions,
		},
	}

	var additionalContainers []*ecs.ContainerDefinition
	for _, container := range p.config.ContainersConfig {
		var secrets []*ecs.Secret
		for k, v := range container.Secrets {
			secrets = append(secrets, &ecs.Secret{
				Name:      aws.String(k),
				ValueFrom: aws.String(v),
			})
		}

		var env []*ecs.KeyValuePair
		for k, v := range container.Environment {
			env = append(env, &ecs.KeyValuePair{
				Name:  aws.String(k),
				Value: aws.String(v),
			})
		}

		c := &ecs.ContainerDefinition{
			Essential: aws.Bool(false),
			Name:      aws.String(container.Name),
			Image:     aws.String(container.Image),
			PortMappings: []*ecs.PortMapping{
				{
					ContainerPort: aws.Int64(int64(container.ContainerPort)),
					HostPort:      aws.Int64(int64(container.HostPort)),
					Protocol:      aws.String(container.Protocol),
				},
			},
			HealthCheck: &ecs.HealthCheck{
				Command:     aws.StringSlice(container.HealthCheck.Command),
				Interval:    aws.Int64(container.HealthCheck.Interval),
				Timeout:     aws.Int64(container.HealthCheck.Timeout),
				Retries:     aws.Int64(container.HealthCheck.Retries),
				StartPeriod: aws.Int64(container.HealthCheck.StartPeriod),
			},
			Secrets:           secrets,
			Environment:       env,
			Memory:            utils.OptionalInt64(int64(container.Memory)),
			MemoryReservation: utils.OptionalInt64(int64(container.MemoryReservation)),
		}

		additionalContainers = append(additionalContainers, c)
	}

	L.Debug("registering task definition", "id", id)

	var cpuShares int
	family := "waypoint-" + app.App

	s.Status("Registering Task definition: %s", family)

	runtime := aws.String("FARGATE")
	if p.config.EC2Cluster {
		runtime = aws.String("EC2")
		cpuShares = p.config.CPU
	} else {
		if err := utils.ValidateEcsMemCPUPair(p.config.Memory, p.config.CPU); err != nil {
			return nil, err
		}

		cpuValues := fargateResources[p.config.Memory]

		// at this point we know that config.CPU is either 0, or a valid value
		// for the memory given
		cpuShares = p.config.CPU
		if cpuShares == 0 {
			cpuShares = cpuValues[0]
		}
	}

	cpus := aws.String(strconv.Itoa(cpuShares))
	// on EC2 launch type, `Cpu` is an optional field, so we leave it nil if it is 0
	if p.config.EC2Cluster && cpuShares == 0 {
		cpus = nil
	}
	mems := strconv.Itoa(p.config.Memory)

	containerDefinitions := append([]*ecs.ContainerDefinition{&def}, additionalContainers...)

	registerTaskDefinitionInput := ecs.RegisterTaskDefinitionInput{
		ContainerDefinitions: containerDefinitions,

		ExecutionRoleArn: aws.String(executionRoleArn),
		Cpu:              cpus,
		Memory:           aws.String(mems),
		Family:           aws.String(family),

		NetworkMode:             aws.String("awsvpc"),
		RequiresCompatibilities: []*string{runtime},

		Tags: []*ecs.Tag{
			{
				Key:   aws.String("waypoint-app"),
				Value: aws.String(app.App),
			},
		},
	}

	if taskRoleArn != "" {
		registerTaskDefinitionInput.SetTaskRoleArn(taskRoleArn)
	}

	var taskOut *ecs.RegisterTaskDefinitionOutput

	// AWS is eventually consistent so even though we probably created the resources that
	// are referenced by the task definition, it can error out if we try to reference those resources
	// too quickly. So we're forced to guard actions which reference other AWS services
	// with loops like this.
	for i := 0; i < 30; i++ {
		taskOut, err = ecsSvc.RegisterTaskDefinition(&registerTaskDefinitionInput)
		if err == nil {
			break
		}

		// if we encounter an unrecoverable error, exit now.
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "ResourceConflictException":
				return nil, err
			}
		}

		// otherwise sleep and try again
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, err
	}

	s.Update("Registered Task definition: %s", family)

	serviceName := fmt.Sprintf("%s-%s", app.App, id)

	// We have to clamp at a length of 32 because the Name field to CreateTargetGroup
	// requires that the name is 32 characters or less.
	if len(serviceName) > 32 {
		serviceName = serviceName[:32]
		L.Debug("using a shortened value for service name due to AWS's length limits", "serviceName", serviceName)
	}

	taskArn := *taskOut.TaskDefinition.TaskDefinitionArn

	var subnets []*string
	var vpcId string
	if len(p.config.Subnets) == 0 {
		s.Update("Using default subnets for Service networking")
		subnets, vpcId, err = defaultSubnets(ctx, sess)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "failed to determine default subnets: %s", err)
		}
	} else {
		subnets = make([]*string, len(p.config.Subnets))
		for i := range p.config.Subnets {
			subnets[i] = &p.config.Subnets[i]
		}

		// We need to determine the vpc id via the API if we were given subnet IDs.
		ec2srv := ec2.New(sess)

		subnetInfo, err := ec2srv.DescribeSubnets(&ec2.DescribeSubnetsInput{
			SubnetIds: subnets,
		})
		if err != nil {
			return nil, err
		}
		if len(subnetInfo.Subnets) == 0 {
			return nil, status.Errorf(codes.FailedPrecondition, "failed to find any subnets with IDs %q", strings.Join(p.config.Subnets, ", "))
		}

		vpcId = *subnetInfo.Subnets[0].VpcId
	}

	var lbArn, tgArn *string
	if !p.config.DisableALB {
		L.Debug("creating security group for ports 80 and 443")
		sgweb, err := createSG(ctx, s, sess, fmt.Sprintf("%s-inbound", app.App), &vpcId, 80, 443)
		if err != nil {
			return nil, err
		}

		lbArn, tgArn, err = createALB(
			ctx, s, L, sess,
			app,
			p.config.ALB,
			&vpcId,
			&serviceName,
			sgweb,
			&p.config.ServicePort,
			subnets,
		)
		if err != nil {
			return nil, err
		}

	}

	// Create the service

	L.Debug("creating service", "arn", *taskOut.TaskDefinition.TaskDefinitionArn)

	if p.config.SecurityGroupIDs == nil {
		sgecsport, err := createSG(ctx, s, sess, fmt.Sprintf("%s-inbound-internal", app.App), &vpcId, int(p.config.ServicePort))
		if err != nil {
			return nil, err
		}

		p.config.SecurityGroupIDs = append(p.config.SecurityGroupIDs, sgecsport)
	}

	count := int64(p.config.Count)
	if count == 0 {
		count = 1
	}

	netCfg := &ecs.AwsVpcConfiguration{
		Subnets:        subnets,
		SecurityGroups: p.config.SecurityGroupIDs,
	}

	if !p.config.EC2Cluster {
		netCfg.AssignPublicIp = aws.String("ENABLED")
	}

	createServiceInput := &ecs.CreateServiceInput{
		Cluster:        &clusterName,
		DesiredCount:   aws.Int64(count),
		LaunchType:     runtime,
		ServiceName:    aws.String(serviceName),
		TaskDefinition: aws.String(taskArn),
		NetworkConfiguration: &ecs.NetworkConfiguration{
			AwsvpcConfiguration: netCfg,
		},
	}

	if !p.config.DisableALB {
		createServiceInput.SetLoadBalancers([]*ecs.LoadBalancer{
			{
				ContainerName:  aws.String(app.App),
				ContainerPort:  aws.Int64(p.config.ServicePort),
				TargetGroupArn: tgArn,
			},
		})
	}

	s.Status("Creating ECS Service (%s, cluster-name: %s)", serviceName, clusterName)

	var servOut *ecs.CreateServiceOutput

	// AWS is eventually consistent so even though we probably created the resources that
	// are referenced by the service, it can error out if we try to reference those resources
	// too quickly. So we're forced to guard actions which reference other AWS services
	// with loops like this.
	for i := 0; i < 30; i++ {
		servOut, err = ecsSvc.CreateService(createServiceInput)
		if err == nil {
			break
		}

		// if we encounter an unrecoverable error, exit now.
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "AccessDeniedException", "UnsupportedFeatureException",
				"PlatformUnknownException",
				"PlatformTaskDefinitionIncompatibilityException":
				return nil, err
			}
		}

		// otherwise sleep and try again
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, err
	}

	s.Update("Created ECS Service (%s, cluster-name: %s)", serviceName, clusterName)
	L.Debug("service started", "arn", servOut.Service.ServiceArn)

	dep := &Deployment{
		Cluster:    clusterName,
		TaskArn:    taskArn,
		ServiceArn: *servOut.Service.ServiceArn,
	}

	// the TargetGroupArn set here is used by Releaser to set the active
	// TargetGroup's weight to 100
	if !p.config.DisableALB {
		dep.TargetGroupArn = *tgArn
		dep.LoadBalancerArn = *lbArn
	}

	return dep, nil
}

func destroyALB(
	ctx context.Context,
	log hclog.Logger,
	sess *session.Session,
	deployment *Deployment,
) error {
	log.Debug("removing deployment target group from load balancer")

	elbsrv := elbv2.New(sess)

	log.Debug("load balancer arn", "arn", deployment.LoadBalancerArn)

	listeners, err := elbsrv.DescribeListeners(&elbv2.DescribeListenersInput{
		LoadBalancerArn: &deployment.LoadBalancerArn,
	})
	if err != nil {
		return err
	}

	var listener *elbv2.Listener

	if len(listeners.Listeners) > 0 {
		listener = listeners.Listeners[0]

		log.Debug("listener arn", "arn", *listener.ListenerArn)

		def := listener.DefaultActions

		var tgs []*elbv2.TargetGroupTuple

		// If there is only 1 target group, delete the listener
		if len(def) == 1 && len(def[0].ForwardConfig.TargetGroups) == 1 {
			log.Debug("only 1 target group, deleting listener")
			_, err = elbsrv.DeleteListener(&elbv2.DeleteListenerInput{
				ListenerArn: listener.ListenerArn,
			})

			if err != nil {
				return err
			}
		} else if len(def) > 1 && def[0].ForwardConfig != nil {
			// Multiple target groups means we can keep the listener
			var active bool

			for _, tg := range def[0].ForwardConfig.TargetGroups {
				if *tg.TargetGroupArn != deployment.TargetGroupArn {
					tgs = append(tgs, tg)
					if *tg.Weight > 0 {
						active = true
					}
				}
			}

			// If there are no target groups active, then we just activate the first
			// one, otherwise we can't modify the listener.
			if !active && len(tgs) > 0 {
				tgs[0].Weight = aws.Int64(100)
			}

			log.Debug("modifying listener to remove target group", "target-groups", len(tgs))

			_, err = elbsrv.ModifyListener(&elbv2.ModifyListenerInput{
				ListenerArn: listener.ListenerArn,
				Port:        listener.Port,
				Protocol:    listener.Protocol,
				DefaultActions: []*elbv2.Action{
					{
						ForwardConfig: &elbv2.ForwardActionConfig{
							TargetGroups: tgs,
						},
						Type: aws.String("forward"),
					},
				},
			})

			if err != nil {
				return err
			}
		}
	}

	log.Debug("deleting target group", "arn", deployment.TargetGroupArn)

	_, err = elbsrv.DeleteTargetGroup(&elbv2.DeleteTargetGroupInput{
		TargetGroupArn: &deployment.TargetGroupArn,
	})
	if err != nil {
		return err
	}

	return nil
}

func (p *Platform) Destroy(
	ctx context.Context,
	log hclog.Logger,
	deployment *Deployment,
	ui terminal.UI,
) error {
	sess, err := utils.GetSession(&utils.SessionConfig{
		Region: p.config.Region,
		Logger: log,
	})
	if err != nil {
		return err
	}

	if deployment.TargetGroupArn != "" && deployment.LoadBalancerArn != "" {
		err = destroyALB(ctx, log, sess, deployment)
		if err != nil {
			return err
		}
	}

	log.Debug("deleting ecs service", "arn", deployment.ServiceArn)

	_, err = ecs.New(sess).DeleteService(&ecs.DeleteServiceInput{
		Cluster: &deployment.Cluster,
		Force:   aws.Bool(true),
		Service: &deployment.ServiceArn,
	})
	if err != nil {
		return err
	}

	return nil
}

type ALBConfig struct {
	// Certificate ARN to attach to the load balancer
	CertificateId string `hcl:"certificate,optional"`

	// Route53 Zone to setup record in
	ZoneId string `hcl:"zone_id,optional"`

	// Fully qualified domain name of the record to create in the target zone id
	FQDN string `hcl:"domain_name,optional"`

	// When set, waypoint will configure the target group into the specified
	// ALB Listener ARN. This allows for usage of existing ALBs.
	ListenerARN string `hcl:"listener_arn,optional"`

	// Indicates, when creating an ALB, that it should be internal rather than
	// internet facing.
	InternalScheme *bool `hcl:"internal,optional"`
}

type HealthCheckConfig struct {
	// A string array representing the command that the container runs to determine if it is healthy
	Command []string `hcl:"command"`

	// The time period in seconds between each health check execution
	Interval int64 `hcl:"interval,optional"`

	// The time period in seconds to wait for a health check to succeed before it is considered a failure
	Timeout int64 `hcl:"timeout,optional"`

	// The number of times to retry a failed health check before the container is considered unhealthy
	Retries int64 `hcl:"retries,optional"`

	// The optional grace period within which to provide containers time to bootstrap before failed health checks count towards the maximum number of retries
	StartPeriod int64 `hcl:"start_period,optional"`
}

type Logging struct {
	CreateGroup bool `hcl:"create_group,optional"`

	StreamPrefix string `hcl:"stream_prefix,optional"`

	DateTimeFormat string `hcl:"datetime_format,optional"`

	MultilinePattern string `hcl:"multiline_pattern,optional"`

	Mode string `hcl:"mode,optional"`

	MaxBufferSize string `hcl:"max_buffer_size,optional"`
}

type ContainerConfig struct {
	// The name of a container
	Name string `hcl:"name"`

	// The image used to start a container
	Image string `hcl:"image"`

	// The amount (in MiB) of memory to present to the container
	Memory int `hcl:"memory,optional"`

	// The soft limit (in MiB) of memory to reserve for the container
	MemoryReservation int `hcl:"memory_reservation,optional"`

	// The port number on the container
	ContainerPort int `hcl:"container_port,optional"`

	// The port number on the container instance to reserve for your container
	HostPort int `hcl:"host_port,optional"`

	// The protocol used for the port mapping
	Protocol string `hcl:"protocol,optional"`

	// The container health check command
	HealthCheck *HealthCheckConfig `hcl:"health_check,block"`

	// The environment variables to pass to a container
	Environment map[string]string `hcl:"static_environment,optional"`

	// The secrets to pass to a container
	Secrets map[string]string `hcl:"secrets,optional"`
}

type Config struct {
	// AWS Region to deploy into
	Region string `hcl:"region"`

	// Name of the Log Group to store logs into
	LogGroup string `hcl:"log_group,optional"`

	// Name of the ECS cluster to install the service into
	Cluster string `hcl:"cluster,optional"`

	// Name of the execution task IAM Role to associate with the ECS Service
	ExecutionRoleName string `hcl:"execution_role_name,optional"`

	// Name of the task IAM role to associate with the ECS service
	TaskRoleName string `hcl:"task_role_name,optional"`

	// Subnets to place the service into. Defaults to the subnets in the default VPC.
	Subnets []string `hcl:"subnets,optional"`

	// Security Group IDs of existing security groups to use for ECS.
	SecurityGroupIDs []*string `hcl:"security_group_ids,optional"`

	// How many tasks of the service to run. Default 1.
	Count int `hcl:"count,optional"`

	// How much memory to assign to the containers
	Memory int `hcl:"memory"`

	// The soft limit (in MiB) of memory to reserve for the container
	MemoryReservation int `hcl:"memory_reservation,optional"`

	// How much CPU to assign to the containers
	CPU int `hcl:"cpu,optional"`

	// The environment variables to pass to the main container
	Environment map[string]string `hcl:"static_environment,optional"`

	// The secrets to pass to to the main container
	Secrets map[string]string `hcl:"secrets,optional"`

	// Assign each task a public IP. Default false.
	// TODO to access ECR you need a nat gateway or a public address and so if you
	// set this to false in the default subnets, ECS can't pull the image. Leaving
	// it disabled until we figure out how to handle that onramp case.
	// AssignPublicIp bool `hcl:"assign_public_ip,optional"`

	// Port that your service is running on within the actual container.
	// Defaults to port 3000.
	ServicePort int64 `hcl:"service_port,optional"`

	// Indicate that service should be deployed on an EC2 cluster.
	EC2Cluster bool `hcl:"ec2_cluster,optional"`

	// If set to true, do not create a load balancer assigned to the service
	DisableALB bool `hcl:"disable_alb,optional"`

	// Configuration options for how the ALB will be configured.
	ALB *ALBConfig `hcl:"alb,block"`

	// Configuration options for additional containers
	ContainersConfig []*ContainerConfig `hcl:"sidecar,block"`

	Logging *Logging `hcl:"logging,block"`
}

func (p *Platform) Documentation() (*docs.Documentation, error) {
	doc, err := docs.New(docs.FromConfig(&Config{}), docs.FromFunc(p.DeployFunc()))
	if err != nil {
		return nil, err
	}

	doc.Description("Deploy the application into an ECS cluster on AWS")

	doc.Example(
		`
deploy {
  use "aws-ecs" {
    region = "us-east-1"
    memory = 512
  }
}
`)

	doc.Input("docker.Image")
	doc.Output("ecs.Deployment")

	doc.SetField(
		"region",
		"the AWS region for the ECS cluster",
	)

	doc.SetField(
		"log_group",
		"the CloudWatchLogs log group to store container logs into",
		docs.Default("derived from the application name"),
	)

	doc.SetField(
		"cluster",
		"the name of the ECS cluster to deploy into",
		docs.Summary(
			"the ECS cluster that will run the application as a Service.",
			"if there is no ECS cluster with this name, the ECS cluster will be",
			"created and configured to use Fargate to run containers.",
		),
	)

	doc.SetField(
		"execution_role_name",
		"the name of the IAM role to use for ECS execution",
		docs.Default("create a new exeuction IAM role based on the application name"),
	)

	doc.SetField(
		"task_role_name",
		"the name of the task IAM role to assign",
	)

	doc.SetField(
		"subnets",
		"the VPC subnets to use for the application",
		docs.Default("public subnets in the default VPC"),
	)

	doc.SetField(
		"security_group_ids",
		"Security Group IDs of existing security groups to use for the ECS service's network access",
		docs.Summary(
			"list of existing group IDs to use for ECS the ECS service's network access",
		),
	)

	doc.SetField(
		"count",
		"how many instances of the application should run",
	)

	doc.SetField(
		"memory",
		"how much memory to assign to the container running the application",
		docs.Summary(
			"when running in Fargate, this must be one of a few values, specified in MB:",
			"512, 1024, 2048, 3072, 4096, 5120, and up to 16384 in increments of 1024.",
			"The memory value also controls the possible values for cpu",
		),
	)

	doc.SetField(
		"ec2_cluster",
		"indicate if the ECS cluster should be EC2 type rather than Fargate",
		docs.Summary(
			"this controls if we should verify the ECS cluster in EC2 type. The cluster",
			"will not be created if it doesn't exist, only that there as existing cluster",
			"this is using EC2 and not Fargate",
		),
	)

	doc.SetField(
		"disable_alb",
		"do not create a load balancer assigned to the service",
	)

	doc.SetField(
		"static_environment",
		"static environment variables to make available",
	)

	doc.SetField(
		"secrets",
		"secret key/values to pass to the ECS container",
	)

	doc.SetField(
		"alb",
		"Provides additional configuration for using an ALB with ECS",
		docs.SubFields(func(doc *docs.SubFieldDoc) {
			doc.SetField(
				"certificate",
				"the ARN of an AWS Certificate Manager cert to associate with the ALB",
			)

			doc.SetField(
				"zone_id",
				"Route53 ZoneID to create a DNS record into",
				docs.Summary(
					"set along with alb.domain_name to have DNS automatically setup for the ALB",
				),
			)

			doc.SetField(
				"domain_name",
				"Fully qualified domain name to set for the ALB",
				docs.Summary(
					"set along with zone_id to have DNS automatically setup for the ALB.",
					"this value should include the full hostname and domain name, for instance",
					"app.example.com",
				),
			)

			doc.SetField(
				"internal",
				"Whether or not the created ALB should be internal",
				docs.Summary(
					"used when listener_arn is not set. If set, the created ALB will have a scheme",
					"of `internal`, otherwise by default it has a scheme of `internet-facing`.",
				),
			)

			doc.SetField(
				"listener_arn",
				"the ARN on an existing ALB to configure",
				docs.Summary(
					"when this is set, no ALB or Listener is created. Instead the application is",
					"configured by manipulating this existing Listener. This allows users to",
					"configure their ALB outside waypoint but still have waypoint hook the application",
					"to that ALB",
				),
			)
		}),
	)

	doc.SetField(
		"logging",
		"Provides additional configuration for logging flags for ECS",
		docs.Summary(
			"Part of the ecs task definition.  These configuration flags help",
			"control how the awslogs log driver is configured."),

		docs.SubFields(func(doc *docs.SubFieldDoc) {
			doc.SetField(
				"create_group",
				"Enables creation of the aws logs group if not present",
			)

			doc.SetField(
				"region",
				"The region the logs are to be shipped to",
				docs.Default("The same region the task is to be running"),
			)

			doc.SetField(
				"stream_prefix",
				"Prefix for application in cloudwatch logs path",
				docs.Default("Generated based off timestamp"),
			)

			doc.SetField(
				"datetime_format",
				"Defines the multiline start pattern in Python strftime format",
			)

			doc.SetField(
				"multiline_pattern",
				"Defines the multiline start pattern using a regular expression",
			)

			doc.SetField(
				"mode",
				"Delivery method for log messages, either 'blocking' or 'non-blocking'",
			)

			doc.SetField(
				"max_buffer_size",
				"When using non-blocking logging mode, this is the buffer size for message storage",
			)
		}),
	)

	doc.SetField(
		"sidecar",
		"Additional container to run as a sidecar.",
		docs.Summary(
			"This runs additional containers in addition to the main container that",
			"comes from the build phase.",
		),
	)

	doc.SetField(
		"sidecar.name",
		"Name of the container",
	)

	doc.SetField(
		"sidecar.image",
		"Image of the sidecar container",
	)

	doc.SetField(
		"sidecar.memory",
		"The amount (in MiB) of memory to present to the container",
	)

	doc.SetField(
		"sidecar.memory_reservation",
		"The soft limit (in MiB) of memory to reserve for the container",
	)

	doc.SetField(
		"sidecar.container_port",
		"The port number for the container",
	)

	doc.SetField(
		"sidecar.host_port",
		"The port number on the host to reserve for the container",
	)

	doc.SetField(
		"sidecar.protocol",
		"The protocol used for port mapping.",
	)

	doc.SetField(
		"sidecar.static_environment",
		"Environment variables to expose to this container",
	)

	doc.SetField(
		"sidecar.secrets",
		"Secrets to expose to this container",
	)

	var memvals []int

	for k := range fargateResources {
		memvals = append(memvals, k)
	}

	sort.Ints(memvals)

	var sb strings.Builder

	for _, mem := range memvals {
		cpu := fargateResources[mem]

		var cpuVals []string

		for _, c := range cpu {
			cpuVals = append(cpuVals, strconv.Itoa(c))
		}

		fmt.Fprintf(&sb, "%dMB: %s\n", mem, strings.Join(cpuVals, ", "))
	}

	doc.SetField(
		"cpu",
		"how many cpu shares the container running the application is allowed",
		docs.Summary(
			"on Fargate, possible values for this are configured by the amount of memory",
			"the container is using. Here is a complete listing of possible values:\n",
			sb.String(),
		),
	)

	doc.SetField(
		"service_port",
		"the TCP port that the application is listening on",
		docs.Default("3000"),
	)

	return doc, nil
}
