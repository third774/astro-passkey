import { actions } from "astro:actions";
import { startAuthentication } from "@simplewebauthn/browser";

export function Login() {
  return (
    <form
      method="POST"
      onSubmit={async (e) => {
        e.preventDefault();
        const username = new FormData(e.currentTarget).get("username");
        if (typeof username !== "string")
          throw new Error("Username was unexpected type");

        const { options } = await actions.authenticateOptions({ username });
        console.log(options, options.rpId, options.extensions);
        const attestationResponse = await startAuthentication(options);
        console.log(attestationResponse);
        const verifyResponse = await actions.authenticateVerify({
          username,
          assertionResponse: attestationResponse,
        });

        // if registration was successful, redirect to root
        if (verifyResponse.user) {
          window.location.replace("/");
        } else {
          alert("Registration failed!");
        }
      }}
    >
      <label htmlFor="username">Username</label>
      <input type="text" name="username" required />
      <button type="submit">Login</button>
    </form>
  );
}
