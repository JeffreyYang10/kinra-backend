import { handleKinraRequest } from "../src/server.mjs";

export default async function handler(request, response) {
  return handleKinraRequest(request, response);
}
