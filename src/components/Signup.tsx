import { actions } from "astro:actions";
import { startRegistration } from "@simplewebauthn/browser";

export function Signup() {
  return (
    <form
      method="POST"
      onSubmit={async (e) => {
        e.preventDefault();
        const username = new FormData(e.currentTarget).get("username");
        if (typeof username !== "string")
          throw new Error("Username was unexpected type");
        const { options } = await actions.registerOptions({ username });
        const attestationResponse = await startRegistration(options);
        console.log(options, options.rp, options.extensions);
        console.log(options, attestationResponse);
        const verifyResponse = await actions.registerVerify({
          username: options.user.name,
          attestationResponse,
        });

        // if registration was successful, redirect to root
        if (verifyResponse.success) {
          window.location.replace("/");
        } else {
          alert("Registration failed!");
        }
      }}
    >
      <label htmlFor="username">Choose a Username</label>
      <input type="text" name="username" required />
      <button type="submit">Register</button>
    </form>
  );
}
