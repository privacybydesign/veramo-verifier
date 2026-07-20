import Debug from 'debug';
import { existsSync } from 'fs';
import { readFile } from 'fs/promises';
import { Request, Response, Router } from 'express';
import { resolveConfPath } from 'utils/resolveConfPath';
import { sendErrorResponse } from 'server/sendErrorResponse';

const debug = Debug('server:staticdid');

// Location, relative to CONF_PATH, of a DID document to expose at the deployment
// root. The dynamic getDidWebSpec handler only serves DID documents under a
// verifier's own sub-path; when a did:web key resolves against the bare host
// (https://<host>/.well-known/did.json) the document has to be provisioned as a
// static file instead. Mount one here to enable that route.
const STATIC_ROOT_DID_CONF_PATH = 'well-known/did.json';

export function serveStaticRootDidDocument(router: Router) {
    const filePath = resolveConfPath(STATIC_ROOT_DID_CONF_PATH);
    if (!existsSync(filePath)) {
        debug('no static DID document at %s, not serving /.well-known/did.json', filePath);
        return;
    }
    debug('serving static DID document at /.well-known/did.json from %s', filePath);
    router.get('/.well-known/did.json', async (_req: Request, res: Response) => {
        try {
            const doc = await readFile(filePath, 'utf8');
            return res.type('application/did+json').send(doc);
        }
        catch (e) {
            return sendErrorResponse(res, 500, 'Invalid DID', e);
        }
    });
}
