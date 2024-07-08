import { defineDb, defineTable, column } from "astro:db";

export const Users = defineTable({
  columns: {
    username: column.text(),
    id: column.text({ primaryKey: true }),
    credentialPublicKey: column.text(),
    credentialID: column.text(),
  },
});

export const Sessions = defineTable({
  columns: {
    id: column.text({ primaryKey: true }),
    challenge: column.text({ optional: true }),
    userId: column.text({
      optional: true,
      references: () => Users.columns.id,
    }),
  },
});

// https://astro.build/db/config
export default defineDb({
  tables: { Sessions, Users },
});
