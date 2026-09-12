// @wc-ignore-file
import {
  validateSetupArguments,
  type SetupDeclaration,
} from "../../browser/lib/src/plugin-setup.js";
import { uuid } from "./model.js";

/** Manual credentials stay with the host; OAuth remains the default connection flow. */
export const setupDeclaration: SetupDeclaration = {
  title: "Connect Notion",
  description: "Connect a Notion database, then review what will sync before making changes.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: ["dataSource"],
    properties: {
      dataSource: {
        type: "string",
        title: "Data source ID",
        description:
          "Use the data source UUID from Notion. Share its database with your Notion connection first.",
        minLength: 1,
      },
    },
  },
};

/** Validate before the installer can create resources or store credentials. */
export function setup(raw: unknown) {
  const args = validateSetupArguments(setupDeclaration, raw);

  return { dataSource: uuid(String(args.dataSource).trim()) };
}
