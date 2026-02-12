import {createLogger} from "@companieshouse/structured-logging-node";
import ApplicationLogger from "@companieshouse/structured-logging-node/lib/ApplicationLogger";

const APP_NAME = "web-security-node";

export const logger: ApplicationLogger = createLogger(APP_NAME);

// Use in original code within log messages
export const LOG_MESSAGE_APP_NAME="CH Web Security Node";
