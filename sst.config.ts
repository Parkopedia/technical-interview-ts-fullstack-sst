/// <reference path="./.sst/platform/config.d.ts" />

export default $config({
  app(input) {
    return {
      name: "ts-fullstack-sst",
      region: "eu-central-1",
      home: "aws",
      providers: {
        aws: {
          profile: "technical-interviews",
        },
      },
    };
  },
  async run() {
    const stripeKey = new sst.Secret("STRIPE_KEY");

    const api = new sst.aws.ApiGatewayV2("Api", {
      transform: {
        route: {
          handler: {
            link: [stripeKey],
          },
        },
      },
    });

    api.route("GET /drivers/{driverId}/get-customer-portal-url", {
      handler: "packages/functions/src/get-customer-portal-url.handler",
    });

    return {
      ApiUrl: api.url,
    };
  },
});
