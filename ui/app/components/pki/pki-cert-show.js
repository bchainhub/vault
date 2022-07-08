import RoleEdit from '../role-edit';
import { inject as service } from '@ember/service';
import { parsePkiCert } from 'vault/helpers/parse-pki-cert';

export default RoleEdit.extend({
  store: service(),
  caChain: null,
  rootCertificate: null,
  issuingMountPath: 'pki',
  path: '/ui/vault/secrets',
  certIsRoot: null,
  mountLink: null,
  async init() {
    this._super(...arguments);
    let adapter = this.store.adapterFor('pki/cert');
    let caChain = [];
    // first find the immediate issuer
    const immediateParentIssuer = await adapter
      .queryIssuingCert(`${this.model.backend}`, 'ca')
      .then(({ data }) => {
        return data;
      });
    caChain.push(immediateParentIssuer);

    // loop until we get to the root, but only loop if not the root
    if (immediateParentIssuer.issuing_mount) {
      this.set('issuingMountPath', immediateParentIssuer.issuing_mount);
      let nextIssuer = immediateParentIssuer;
      do {
        let response;
        response = await adapter
          .queryIssuingCert(`${immediateParentIssuer.issuing_mount}`, 'ca')
          .then(({ data }) => {
            return data;
          });
        nextIssuer = response;
        caChain.push(nextIssuer);
      } while (nextIssuer.issuing_mount !== undefined);
    }
    // parse the array of certificates
    let parsedCaChain = caChain.map((cert) => parsePkiCert([cert, true]));

    // if only one cert in the array, it's the root
    if (caChain.length === 1) {
      this.set('rootCertificate', parsedCaChain[0]);
    }

    // if the serial numbers are equal, then we're viewing the root cert
    if (this.model.serialNumber === parsedCaChain[0].serial_number) {
      this.set('certIsRoot', true);
    }

    // otherwise it's the last element
    if (caChain.length > 1) {
      let root = parsedCaChain[parsedCaChain.length - 1];
      parsedCaChain.pop();
      this.set('rootCertificate', root);
      this.set('caChain', parsedCaChain);
    }

    let origin =
      window.location.protocol +
      '//' +
      window.location.hostname +
      (window.location.port ? ':' + window.location.port : '');
    this.set('mountLink', origin + this.path + '/' + this.issuingMountPath + '/show/cert/');
  },
  actions: {
    delete() {
      this.model.save({ adapterOptions: { method: 'revoke' } });
    },
  },
});
