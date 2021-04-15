import {
  EngineType,
  FormattedResult,
  IaCErrorCodes,
  IacFileScanResult,
  IaCTestFlags,
  PolicyMetadata,
} from './types';
import * as path from 'path';
import { SEVERITY } from '../../../../lib/snyk-test/common';
import {
  IacProjectType,
  projectTypeByFileType,
} from '../../../../lib/iac/constants';
import { CustomError } from '../../../../lib/errors';
import { extractLineNumber } from './extract-line-number';

const SEVERITIES = [SEVERITY.LOW, SEVERITY.MEDIUM, SEVERITY.HIGH];

export async function formatScanResults(
  scanResults: IacFileScanResult[],
  options: IaCTestFlags,
): Promise<FormattedResult[]> {
  try {
    // Relevant only for multi-doc yaml files
    const scannedResultsGroupedByDocId = groupMultiDocResults(scanResults);
    return scannedResultsGroupedByDocId.map((iacScanResult) =>
      formatScanResult(iacScanResult, options.severityThreshold),
    );
  } catch (e) {
    throw new FailedToFormatResults();
  }
}

const engineTypeToProjectType = {
  [EngineType.Kubernetes]: IacProjectType.K8S,
  [EngineType.Terraform]: IacProjectType.TERRAFORM,
};

function formatScanResult(
  scanResult: IacFileScanResult,
  severityThreshold?: SEVERITY,
): FormattedResult {
  const formattedIssues = scanResult.violatedPolicies.map((policy) => {
    const cloudConfigPath =
      scanResult.docId !== undefined
        ? [`[DocId:${scanResult.docId}]`].concat(policy.msg.split('.'))
        : policy.msg.split('.');

    const lineNumber: number = extractLineNumber(scanResult, policy);

    return {
      ...policy,
      id: policy.publicId,
      name: policy.title,
      cloudConfigPath,
      isIgnored: false,
      iacDescription: {
        issue: policy.issue,
        impact: policy.impact,
        resolve: policy.resolve,
      },
      severity: policy.severity,
      lineNumber,
    };
  });

  const targetFilePath = path.resolve(scanResult.filePath, '.');
  return {
    result: {
      cloudConfigResults: filterPoliciesBySeverity(
        formattedIssues,
        severityThreshold,
      ),
      projectType: projectTypeByFileType[scanResult.fileType],
    },
    isPrivate: true,
    packageManager: engineTypeToProjectType[scanResult.engineType],
    targetFile: scanResult.filePath,
    targetFilePath,
    vulnerabilities: [],
    dependencyCount: 0,
    licensesPolicy: null,
    ignoreSettings: null,
    projectName: path.basename(path.dirname(targetFilePath)),
  };
}

function groupMultiDocResults(
  scanResults: IacFileScanResult[],
): IacFileScanResult[] {
  const groupedData = scanResults.reduce((memo, result) => {
    if (memo[result.filePath]) {
      memo[result.filePath].violatedPolicies = memo[
        result.filePath
      ].violatedPolicies.concat(result.violatedPolicies);
    } else {
      memo[result.filePath] = result;
    }

    return memo;
  }, {} as IacFileScanResult);

  return Object.values(groupedData);
}

function filterPoliciesBySeverity(
  violatedPolicies: PolicyMetadata[],
  severityThreshold?: SEVERITY,
): PolicyMetadata[] {
  if (!severityThreshold || severityThreshold === SEVERITY.LOW) {
    return violatedPolicies.filter((violatedPolicy) => {
      return violatedPolicy.severity !== ('none' as SEVERITY);
    });
  }

  const severitiesToInclude = SEVERITIES.slice(
    SEVERITIES.indexOf(severityThreshold),
  );
  return violatedPolicies.filter((policy) => {
    return (
      severitiesToInclude.includes(policy.severity) ||
      policy.severity !== ('none' as SEVERITY)
    );
  });
}

export class FailedToFormatResults extends CustomError {
  constructor(message?: string) {
    super(message || 'Failed to format results');
    this.code = IaCErrorCodes.FailedToFormatResults;
    this.userMessage =
      'We failed printing the results, please contact support@snyk.io';
  }
}
