import {Router} from 'express';
import {handleIssuanceError} from '../lib/util';

const util = require('util');
const {assertValidIssuanceCredential, getRequestedIssuer} = require('../lib/credentialService');
const factomDid = require('../resources/factomDid.json');
const {issueFactomCredential} = require('../lib/factomService');
const veresOneDid = require('../resources/veresOneDid');
const {issueVeresCredential} = require('../lib/veresOneService');

export default ({ config }) => {
	let api = Router();

	// Internal Endpoints

	/*	Issue new credential
		Issues a credential and returns it in the response body.
		Support of this part of the API is REQUIRED for implementations.
	*/
	api.post('/credentials', async (req, res) => {
		if(!req.body.credential){
			res.status(400).send("No credential specified in request");
		}

		const credential = req.body.credential;
		const options = req.body.options;

		//check credential
		try{
			assertValidIssuanceCredential(credential);
		} catch(err){
			handleIssuanceError(res, err);
			return;
		}

		//extract issuer from options
		const requestedIssuer = await getRequestedIssuer(options)
			.catch(err => {
				handleIssuanceError(res, err);
				return false;
			});
		if(!requestedIssuer){
			return;
		}
		switch(requestedIssuer){
			case factomDid.identity.did:
				return issueFactomCredential(credential)
					.then(result => res.status(201).send(result))
					.catch(err => handleIssuanceError(res, err));
			case veresOneDid.did:
				return issueVeresCredential(credential)
					.then(result => res.status(201).send(result))
					.catch(err => handleIssuanceError(res, err, req));
			default:
				return res.status(400).send("Unknown issuer did");
		}
	});

	/*	Compose and issue new credential
		Composes and issues a credential and returns it in the response body.
		Support of this part of the API is OPTIONAL for implementations.
	*/
	api.post('/composeAndIssueCredential', (req, res) => {
		// not yet implemented

		res.send(req.params);
	});

	return api;
};
