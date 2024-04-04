import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { Config } from "sst/node/config";
import Stripe from "stripe";

const stripe = new Stripe(Config.STRIPE_KEY, {
  apiVersion: "2023-10-16",
});

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const driverId = event.pathParameters?.driverId;
  const customers = await stripe.customers.search({
    query: `metadata['ppDriverId']:'${driverId}'`,
  });

  if (customers.data.length === 0) {
    return {
      statusCode: 404,
      body: JSON.stringify({
        message: `No customer found with driverId ${driverId}`,
      }),
    };
  }

  const customer = customers.data[0] as Stripe.Customer;
  const session = await stripe.billingPortal.sessions.create({
    customer: customer.id,
    return_url: "https://example.com/account",
  });

  return {
    statusCode: 200,
    body: JSON.stringify({
      driverId,
      url: session.url,
    }),
  };
};
