const PASSWORD = "<YOUR PASSWORD>";

export default {
  async fetch(request, env) {
    const auth = request.headers.get("Authorization");

    if (auth) {
      const [scheme, encoded] = auth.split(" ");
      if (scheme === "Basic" && encoded) {
        const decoded = atob(encoded);
        const [, password] = decoded.split(":");
        if (password === PASSWORD) {
          return env.ASSETS.fetch(request);
        }
      }
    }

    return new Response("Unauthorized", {
      status: 401,
      headers: { "WWW-Authenticate": 'Basic realm="Fuzz Dashboard"' },
    });
  },
};
