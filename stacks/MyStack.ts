import { StackContext, Api, Config } from "sst/constructs";

export function API({ stack }: StackContext) {
  const STRIPE_KEY = new Config.Secret(stack, "STRIPE_KEY");

  const api = new Api(stack, "api", {
    defaults: {
      function: {
        bind: [STRIPE_KEY],
      },
    },
    routes: {
      "GET /drivers/{driverId}/get-customer-portal-url":
        "packages/functions/src/get-customer-portal-url.handler",
    },
  });

  stack.addOutputs({
    ApiUrl: api.url,
  });
}
