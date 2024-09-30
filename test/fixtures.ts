import { SodiumWrapper } from "@nmshd/crypto";

export const mochaHooks = {
    beforeAll: async (): Promise<void> => {
        await SodiumWrapper.ready();
    }
};
