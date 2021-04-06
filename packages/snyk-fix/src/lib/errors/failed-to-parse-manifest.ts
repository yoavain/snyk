import { reTryMessage } from './common';
import { CustomError, ERROR_CODES } from './custom-error';

export class FailedToParseManifest extends CustomError {
  public constructor() {
    super(
      'Failed to parse manifest. ' + reTryMessage,
      ERROR_CODES.FailedToParseManifest,
    );
  }
}
