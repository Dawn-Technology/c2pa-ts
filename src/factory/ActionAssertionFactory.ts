import { Action, ActionAssertion, ActionType, Manifest } from '../manifest';

export class ActionAssertionFactory {
    /**
     * Builds an ActionAssertion indicating that the asset was opened, with the provided actions, and adds it to the manifest.
     */
    public static add(manifest: Manifest, actions: ActionType[] = []): ActionAssertion {
        const instanceID = manifest.claim?.instanceID;
        const actionAssertion = new ActionAssertion();
        const openedAction: Action = {
            action: ActionType.C2paOpened,
            instanceID,
            parameters: {
                ingredients: [manifest.createHashedReference(`c2pa.assertions/c2pa.ingredient`)],
            },
        };

        actionAssertion.actions.push(openedAction);

        for (const action of actions) {
            if (action === ActionType.C2paOpened) continue; // already added

            actionAssertion.actions.push({
                action: action,
                instanceID,
            });
        }

        manifest.addAssertion(actionAssertion);
        return actionAssertion;
    }
}
