import { IaCErrorCodes, IacFileScanResult, IacOrgSettings } from './types';
import { Payload } from '../../../../lib/snyk-test/types';
import * as config from '../../../../lib/config';
import { isCI } from '../../../../lib/is-ci';
import { api } from '../../../../lib/api-token';
import request = require('../../../../lib/request');
import { CustomError } from '../../../../lib/errors';
import _ = require('lodash');

/*
 * Fetches custom policies (updated severities) and some org metadata
 * If there is an error, it fails with a user friendly error
 */
export function getIacOrgSettings(): Promise<IacOrgSettings> {
  const payload: Payload = {
    method: 'get',
    url: config.API + '/iac-org-settings',
    json: true,
    headers: {
      'x-is-ci': isCI(),
      authorization: `token ${api()}`,
    },
  };

  return new Promise((resolve, reject) => {
    request(payload, (error, res) => {
      if (error) {
        return reject(error);
      }
      if (res.statusCode < 200 || res.statusCode > 299) {
        return reject(new FailedToGetIacOrgSettings());
      }
      resolve(res.body);
    });
  });
}

export async function applyCustomSeverities(
  scannedFiles: IacFileScanResult[],
): Promise<IacFileScanResult[]> {
  const iacOrgSettings: IacOrgSettings = await getIacOrgSettings();
  if (iacOrgSettings.hasOwnProperty('error')) {
    return scannedFiles;
  }
  const customPolicies: Record<string, string> = iacOrgSettings.customPolicies;

  return scannedFiles.map((file) => {
    const updatedScannedFiles = _.cloneDeep(file);
    updatedScannedFiles.violatedPolicies.forEach((existingPolicy) => {
      const customPolicyPublicId = customPolicies[existingPolicy.publicId];
      if (customPolicyPublicId) {
        existingPolicy.severity = customPolicyPublicId['severity'];
      }
    });
    return updatedScannedFiles;
  });
}

export class FailedToGetIacOrgSettings extends CustomError {
  constructor(message?: string) {
    super(message || 'Failed to fetch IaC organization settings');
    this.code = IaCErrorCodes.FailedToGetIacOrgSettings;
    this.userMessage =
      'We failed to fetch IaC organization settings, including custom severity overrides. Please run the command again with the `-d` flag and contact support@snyk.io with the contents of the output.';
  }
}
