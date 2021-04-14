import { CustomPoliciesWithMeta, IacFileScanResult } from './types';
import { Payload } from '../../../../lib/snyk-test/types';
import * as config from '../../../../lib/config';
import { isCI } from '../../../../lib/is-ci';
import request = require('../../../../lib/request');
import { api} from '../../../../lib/api-token';

export async function filterFilesByCustomPolicies(
  scannedFiles: IacFileScanResult[],
): Promise<IacFileScanResult[]> {
  const filteredResults: IacFileScanResult[] = [];

  const iacOrgSettings: CustomPoliciesWithMeta = await getIacOrgSettings();
  // update the scannedFiles based on the iacOrgSettings.customPolicies
  return filteredResults;
}

function getIacOrgSettings(): Promise<CustomPoliciesWithMeta> {
  const payload: Payload = {
    method: 'get',
    url: config.API + '/iac-org-settings',
    json: true,
    headers: {
      'x-is-ci': isCI(),
      'authorization': `token ${api()}`,
    },
  };

  return new Promise((resolve, reject) => {
    request(payload, (error, res) => {
      if (error) {
        return reject(error);
      }
      resolve(res.body);
    });
  });
}
