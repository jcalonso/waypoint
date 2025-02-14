import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { Project, Variable } from 'waypoint-pb';
import { inject as service } from '@ember/service';
import ApiService from 'waypoint/services/api';
import RouterService from '@ember/routing/router-service';
import PdsFlashMessages from 'waypoint/services/flash-messages';

interface ProjectSettingsArgs {
  project: Project.AsObject;
}

export default class ProjectInputVariablesListComponent extends Component<ProjectSettingsArgs> {
  @service api!: ApiService;
  @service router!: RouterService;
  @service flashMessages: PdsFlashMessages;
  @tracked project: Project.AsObject;
  @tracked variablesList: Array<Variable.AsObject>;
  @tracked isCreating: boolean;
  @tracked activeVariable;

  constructor(owner: any, args: any) {
    super(owner, args);
    let { project } = args;
    this.project = project;
    this.variablesList = this.project.variablesList;
    this.activeVariable = null;
    this.isCreating = false;
  }

  @action
  addVariable() {
    this.isCreating = true;
    let newVar = new Variable();
    // Seems like setServer (with empty arguments?) is required to make it a server variable
    newVar.setServer();
    let newVarObj = newVar.toObject();
    this.variablesList = [newVarObj, ...this.variablesList];
    this.activeVariable = newVarObj;
  }

  @action
  async deleteVariable(variable) {
    this.variablesList = this.variablesList.filter((v) => v.name !== variable.name);
    await this.saveVariableSettings();
  }

  @action
  cancelCreate() {
    this.activeVariable = null;
    this.isCreating = false;
  }

  @action
  async saveVariableSettings(
    variable?: Variable.AsObject,
    initialVariable?: Variable.AsObject
  ): Promise<Project.AsObject | void> {
    try {
      let resp = await this.api.upsertProject(
        this.project,
        undefined,
        variable,
        initialVariable,
        this.variablesList
      );

      this.project = resp;
      this.flashMessages.success('Settings saved');
      this.activeVariable = null;
      this.isCreating = false;
      this.router.refresh('workspace.projects.project');

      return resp;
    } catch (err) {
      this.flashMessages.error('Failed to save Settings', { content: err.message, sticky: true });
      return;
    }
  }
}
