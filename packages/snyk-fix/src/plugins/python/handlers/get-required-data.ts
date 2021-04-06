import { MissingRemediationDataError } from '../../../lib/errors/missing-remediation-data';
import { MissingFileNameError } from '../../../lib/errors/missing-file-name';
import { EntityToFix, RemediationChanges, Workspace } from '../../../types';
import { NoFixesCouldBeAppliedError } from '../../../lib/errors/no-fixes-applied';

export function getRequiredData(
  entity: EntityToFix,
): {
  remediation: RemediationChanges;
  targetFile: string;
  workspace: Workspace;
} {
  const { remediation } = entity.testResult;
  if (!remediation) {
    throw new MissingRemediationDataError();
  }
  const { targetFile } = entity.scanResult.identity;
  if (!targetFile) {
    throw new MissingFileNameError();
  }
  const { workspace } = entity;
  if (!workspace) {
    throw new NoFixesCouldBeAppliedError();
  }
  return { targetFile, remediation, workspace };
}
