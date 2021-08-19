package cli

import (
	"strconv"
	"strings"

	"github.com/posener/complete"

	"github.com/hashicorp/waypoint-plugin-sdk/terminal"
	"github.com/hashicorp/waypoint/internal/clierrors"
	"github.com/hashicorp/waypoint/internal/cliformat"
	"github.com/hashicorp/waypoint/internal/pkg/flag"
	pb "github.com/hashicorp/waypoint/internal/server/gen"
)

type ProjectInspectCommand struct {
	*baseCommand

	flagJson bool
}

func (c *ProjectInspectCommand) Run(args []string) int {
	flagSet := c.Flags()
	// Initialize. If we fail, we just exit since Init handles the UI.
	if err := c.Init(
		WithArgs(args),
		WithFlags(flagSet),
		WithConfig(true), // optional config loading
	); err != nil {
		return 1
	}

	cmdArgs := flagSet.Args()
	var projectTarget string
	if len(cmdArgs) > 1 {
		c.ui.Output("No more than 1 argument required.\n\n"+c.Help(), terminal.WithErrorStyle())
		return 1
	} else if len(cmdArgs) == 0 {
		// If we're in a project dir, load the name. Otherwise we'll
		// try the arg passed in
		if c.project.Ref() != nil {
			projectTarget = c.project.Ref().Project
		} else {
			c.ui.Output("Project argument required, and not in a project directory..\n\n"+
				c.Help(), terminal.WithErrorStyle())
			return 1
		}
	} else if len(cmdArgs) == 1 {
		// project requested
		projectTarget = cmdArgs[0]
	}

	err := c.FormatProject(projectTarget)
	if err != nil {
		c.ui.Output("Failed to format project: %s"+
			clierrors.Humanize(err),
			terminal.WithErrorStyle())
		return 1
	}
	return 0
}

func (c *ProjectInspectCommand) FormatProject(projectTarget string) error {
	// Get our API client
	client := c.project.Client()

	resp, err := client.GetProject(c.Ctx, &pb.GetProjectRequest{
		Project: &pb.Ref_Project{
			Project: projectTarget,
		},
	})
	if err != nil {
		return err
	}
	project := resp.Project
	workspaces := resp.Workspaces

	var appNames []string
	for _, app := range project.Applications {
		appNames = append(appNames, app.Name)
	}

	var workspaceNames []string
	for _, ws := range workspaces {
		workspaceNames = append(workspaceNames, ws.Workspace.Workspace)
	}

	var gitUrl, gitRef, gitPath string
	dataSource := "Local" // if unset, assume local
	if project.DataSource != nil {
		switch ds := project.DataSource.Source.(type) {
		case *pb.Job_DataSource_Local:
			dataSource = "Local"
		case *pb.Job_DataSource_Git:
			dataSource = "Git"

			gitUrl = ds.Git.Url
			gitRef = ds.Git.Ref
			gitPath = ds.Git.Path
		}
	}

	var datasourcePollEnabled bool
	var datasourcePollInterval string
	if project.DataSourcePoll != nil {
		datasourcePollEnabled = project.DataSourcePoll.Enabled
		datasourcePollInterval = project.DataSourcePoll.Interval
	}

	var appPollEnabled bool
	var appPollInterval string
	if project.StatusReportPoll != nil {
		appPollEnabled = project.StatusReportPoll.Enabled
		appPollInterval = project.StatusReportPoll.Interval
	}

	fileChangeSignal := project.FileChangeSignal

	if c.flagJson {
		projectHeaders := []string{
			"Project", "Applications", "Workspaces", "Remote Enabled", "Data Source",
			"Git URL", "Git Ref", "Git Path", "Data Source Poll Enabled",
			"Data Source Poll Interval", "App Status Poll Enabled", "App Status Poll Interval",
			"File Change Signal",
		}

		projectTbl := terminal.NewTable(projectHeaders...)

		statusColor := ""
		columns := []string{
			project.Name,
			strings.Join(appNames, ", "),
			strings.Join(workspaceNames, ", "),
			strconv.FormatBool(project.RemoteEnabled),
			dataSource,
			gitUrl,
			gitRef,
			gitPath,
			strconv.FormatBool(datasourcePollEnabled),
			datasourcePollInterval,
			strconv.FormatBool(appPollEnabled),
			appPollInterval,
			fileChangeSignal,
		}

		projectTbl.Rich(
			columns,
			[]string{
				statusColor,
			},
		)

		data, err := cliformat.FormatTableJson(projectTbl)
		if err != nil {
			return err
		}
		c.ui.Output(data)
	} else {
		// Show project info in a flat list where each project option is its
		// own row
		c.ui.Output("Project Info:", terminal.WithHeaderStyle())

		// Unset value strings will be omitted automatically
		c.ui.NamedValues([]terminal.NamedValue{
			{
				Name: "Project Name", Value: project.Name,
			},
			{
				Name: "Applications", Value: strings.Join(appNames, ", "),
			},
			{
				Name: "Workspaces", Value: strings.Join(workspaceNames, ", "),
			},
			{
				Name: "Remote Enabled", Value: strconv.FormatBool(project.RemoteEnabled),
			},
			{
				Name: "Data Source", Value: dataSource,
			},
			{
				Name: "Git URL", Value: gitUrl,
			},
			{
				Name: "Git Ref", Value: gitRef,
			},
			{
				Name: "Git Path", Value: gitPath,
			},
			{
				Name: "Data Source Poll Enabled", Value: strconv.FormatBool(datasourcePollEnabled),
			},
			{
				Name: "Data Source Poll Interval", Value: datasourcePollInterval,
			},
			{
				Name: "App Status Poll Enabled", Value: strconv.FormatBool(appPollEnabled),
			},
			{
				Name: "App Status Poll Interval", Value: appPollInterval,
			},
			{
				Name: "File Change Signal", Value: fileChangeSignal,
			},
		}, terminal.WithInfoStyle())

	}
	return nil
}

func (c *ProjectInspectCommand) Flags() *flag.Sets {
	return c.flagSet(0, func(sets *flag.Sets) {
		f := sets.NewSet("Command Options")

		f.BoolVar(&flag.BoolVar{
			Name:   "json",
			Target: &c.flagJson,
			Usage:  "Output project information as JSON.",
		})
	})
}

func (c *ProjectInspectCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *ProjectInspectCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ProjectInspectCommand) Synopsis() string {
	return "Inspect the details of a project."
}

func (c *ProjectInspectCommand) Help() string {
	return formatHelp(`
Usage: waypoint project inspect [project-name]

  Inspect the details of a given project.

  Projects usually map to a single version control repository and contain
  exactly one "waypoint.hcl" configuration. A project may contain multiple
  applications.

  A project is registered via the web UI, "waypoint project apply",
  or "waypoint init".

` + c.Flags().Help())
}
