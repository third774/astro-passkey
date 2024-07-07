import { asDrizzleTable } from "@astrojs/db/utils";
import { defineDb, defineTable, column } from "astro:db";

const UsersTable = defineTable({
  columns: {
    username: column.text(),
    id: column.text({ primaryKey: true }),
    credentialPublicKey: column.text(),
    credentialID: column.text(),
  },
});

const SessionsTable = defineTable({
  columns: {
    id: column.text({ primaryKey: true }),
    challenge: column.text({ optional: true }),
    userId: column.text({
      optional: true,
      references: () => UsersTable.columns.id,
    }),
  },
});

// https://astro.build/db/config
export default defineDb({
  tables: { Sessions: SessionsTable, Users: UsersTable },
});

export const Sessions = asDrizzleTable("Sessions", SessionsTable);
export const Users = asDrizzleTable("Users", UsersTable);
