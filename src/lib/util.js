/**	Creates a callback that proxies node callback style arguments to an Express Response object.
 *	@param {express.Response} res	Express HTTP Response
 *	@param {number} [status=200]	Status code to send on success
 *
 *	@example
 *		list(req, res) {
 *			collection.find({}, toRes(res));
 *		}
 */
export function toRes(res, status=200) {
	return (err, thing) => {
		if (err) return res.status(500).send(err);

		if (thing && typeof thing.toObject==='function') {
			thing = thing.toObject();
		}
		res.status(status).json(thing);
	};
}

export function handleIssuanceError(res, err){
	if(err.code && err.message){
		res.status(err.code).send({message: err.message});
		return;
	}
	if(err.message === 'https://www.w3.org/2018/credentials/v1 needs to be first in the list of contexts.'){
		res.status(400).send({message: "invalid context"});
		return;
	}
	if(err.name === 'jsonld.InvalidUrl'){
		res.status(400).send({message: 'invalid context'});
		return;
	}
	if(err.details && err.details.code === 'loading remote context failed'){
		res.status(400).send({message: 'invalid context'});
		return;
	}
	res.status(500).send({message: "Could not issue credential: "+ err.toString()});
}

export function handleVerificationError(res, err){
	if(err.code && err.message){
		res.status(err.code).send({message: err.message});
		return;
	}
	if(Array.isArray(err)){
		err = err[0];
	}
	if(err.name === 'VerificationError' || err.errors){
		if(err.errors.length){
			if(err.errors[0].message === "Invalid signature."){
				res.status(400).send({message: "Invalid signature."});
				return;
			}
			if(err.errors[0].message === 'Could not verify any proofs; no proofs matched the required suite and purpose.'){
				res.status(400).send({message: 'Malformed proof.'});
				return;
			}
			if(err.errors[0].message.includes('in the input was not defined in the context.')){
				res.status(400).send({message: 'Malformed proof.'});
				return;
			}
		}
	}
	if(!err.message){
		res.status(500).send({message: 'Could not verify credential.'});
		return;
	}
	if(err.message.includes('property is required.')){
		res.status(400).send({message: 'Missing property.'});
		return;
	}
	if(err.message.includes('id must be a URL')){
		res.status(400).send({message: 'Property must be a url'});
		return;
	}
	res.status(500).send({message: 'Could not verify credential.'});
	return;
}
