import Route from '@ember/routing/route';

export default class VaultClusterOidcProviderRoute extends Route {
  beforeModel(transition) {
    // This is called on both this route and the child route,
    // so we only want to transition to the child with a dummy
    // namespace if this route is the destination
    if (transition.to.name === 'vault.cluster.oidc-provider.index') {
      return this.transitionTo('vault.cluster.oidc-provider.authz', encodeURIComponent(' '));
    }
  }
}
