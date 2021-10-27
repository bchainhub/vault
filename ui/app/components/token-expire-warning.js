import Component from '@glimmer/component';
import { inject as service } from '@ember/service';

export default class TokenExpireWarning extends Component {
  @service router;

  get showWarning() {
    let currentRoute = this.router.currentRouteName;
    if (currentRoute.startsWith('vault.cluster.oidc-provider')) {
      return false;
    }
    return !!this.args.expirationDate;
  }
}
