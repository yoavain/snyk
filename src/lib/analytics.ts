import * as snyk from '../lib';
import * as config from './config';
import * as version from './version';
import * as request from './request';
import {isCI} from './is-ci';
import * as Debug from 'debug';
import * as os from 'os';
import osName = require('os-name');
import * as crypto from 'crypto';
import * as uuid from 'uuid';

const debug = Debug('snyk');

let metadata = {};
// analytics module is required at the beginning of the CLI run cycle
const startTime = Date.now();

export function analytics(data: AnalyticsData) {
  let analyticsData = data;
  if (!analyticsData) {
    analyticsData = {};
  }

  // merge any new data with data we picked up along the way
  if (Array.isArray(data.args)) {
    // this is an overhang from the cli/args.js and we don't want it
    delete (data.args.slice(-1).pop() || [])._;
  }

  if (Object.keys(analyticsData).length) {
    analyticsData.metadata = metadata;
  }

  return postAnalytics(analyticsData);
}

interface AnalyticsData {
  durationMs?: number;
  version?: number;
  os?: string;
  nodeVersion?: string;
  id?: string;
  ci?: boolean;
  metadata?: object;
  command?: string;
  args?: any; // TODO: define the type for all cli args in analytics
}

export async function postAnalytics(data) {
  const analyticsData = {} as AnalyticsData;
  // if the user opt'ed out of analytics, then let's bail out early
  // ths applies to all sending to protect user's privacy
  if (snyk.config.get('disable-analytics') || config.DISABLE_ANALYTICS) {
    debug('analytics disabled');
    return Promise.resolve();
  }

  try {
    const snykVersion = await version();
    analyticsData.version = snykVersion;
    analyticsData.os = osName(os.platform(), os.release());
    analyticsData.nodeVersion = process.version;

    const seed = uuid.v4();
    const shasum = crypto.createHash('sha1');
    analyticsData.id = shasum.update(seed).digest('hex');

    const headers: {
      authorization?: string;
    } = {};
    if (snyk.api) {
      headers.authorization = 'token ' + snyk.api;
    }

    analyticsData.ci = isCI();
    analyticsData.durationMs = Date.now() - startTime;

    debug('analytics', data);

    return request({
      body: {
        data: analyticsData,
      },
      url: config.API + '/analytics/cli',
      json: true,
      method: 'post',
      headers,
    });
  } catch (error) {
    debug('analytics', error); // this swallows the analytics error
  }
}

analytics.reset = () => {
  metadata = {};
};

analytics.add = (key, value) => {
  debug('analytics trying to add meta', key, value);
  if (metadata[key]) {
    if (!Array.isArray(metadata[key])) {
      metadata[key] = [metadata[key]];
    }
    metadata[key].push(value);
  } else {
    metadata[key] = value;
  }
};
