import { SSTConfig } from "sst";
import { API } from "./stacks/MyStack";

export default {
  config(_input) {
    return {
      name: "ts-fullstack-sst",
      region: "eu-central-1",
      profile: "technical-interviews",
    };
  },
  stacks(app) {
    app.stack(API);
  },
} satisfies SSTConfig;
