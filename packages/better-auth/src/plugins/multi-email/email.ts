import type { GenericEndpointContext } from "@better-auth/core";
import type{MultiEmailOptions} from "./types";

export async function addEmail(
    ctx: GenericEndpointContext,
    opts: MultiEmailOptions,
){
    const { email }: { email: string } = ctx.body;
}