import {Router} from 'express';
import {handleVerificationError} from '../lib/util';

const {verifyCredential, verifyPresentation} = require('../lib/verificationService');
const {verifyCredentialStructure} = require('../lib/credentialService');

export default ({ config }) => {
	let api = Router();

	// Internal Endpoints

	/*	Verify a credential
		Performs a series of verification checks on a provided Verifiable Credential
		and returns the overall status of the checks as well as the status of each individual check.
		Support of this part of the API is REQUIRED for implementations.
	*/
	api.post('/credentials', (req, res) => {
		// Receive External Credential and Signature
		// Verify Context
		// Verify Credential
		// - Require: Issuer, IssuanceDate, CredentialSubject
		// - Verify Issuer DID (Uniresolver)

		// check requirements

		const {verifiableCredential, options} = req.body;

		try{
			verifyCredentialStructure(verifiableCredential);
		} catch (err){
			handleVerificationError(res, err);
			return;
		}
		return verifyCredential(verifiableCredential)
			.then(result => res.status(200).send(result))
			.catch(err => handleVerificationError(res, err));
	});


	/*	Verify a Presentation
		Performs a series of verification checks on a provided Verifiable Presentation
		and returns the overall status of the checks as well as the status of each individual check.
		Support of this part of the API is OPTIONAL for implementations.
	*/
	api.post('/presentations', (req, res) => {
		// Receive Signed Claims
		// Verify Claims
		// - Require:

		const {verifiablePresentation, options} = req.body;

		if(!verifiablePresentation){
			res.status(400).send({message: "invalid input!"});
			return;
		}

		if(!options || !options.challenge){
			res.status(400).send({message: "Request should contain a challenge."});
			return;
		}

		return verifyPresentation(verifiablePresentation, options.challenge)
			.then(verification => res.status(200).send(verification))
			.catch(err => handleVerificationError(res, err));
	});

	return api;
};
