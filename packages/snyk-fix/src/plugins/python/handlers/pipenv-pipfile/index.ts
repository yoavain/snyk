import * as debugLib from 'debug';
import { EntityToFix, FixOptions } from '../../../../types';
import { PluginFixResponse } from '../../../types';
import { partitionByFixable } from '../is-supported';
import { updateDependencies } from './update-dependencies';

const debug = debugLib('snyk-fix:python:Pipfile');

export async function pipenvPipfile(
  entities: EntityToFix[],
  options: FixOptions,
): Promise<PluginFixResponse> {
  debug(`Preparing to fix ${entities.length} Python Pipfile projects`);
  const handlerResult: PluginFixResponse = {
    succeeded: [],
    failed: [],
    skipped: [],
  };
  // TODO: ensure pipenv is installed
  // bail if not
  const { fixable, skipped: notFixable } = await partitionByFixable(entities);
  handlerResult.skipped.push(...notFixable);

  for (const entity of fixable) {
    const { failed, succeeded, skipped } = await updateDependencies(
      entity,
      options,
    );
    handlerResult.succeeded.push(...succeeded);
    handlerResult.failed.push(...failed);
    handlerResult.skipped.push(...skipped);
  }

  return handlerResult;
}
