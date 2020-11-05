import GitHubApi from 'github-api';
import Promise from 'promise';
import InvalidRevocationOptions from "../../error/InvalidRevocationOptions";
import CredentialLoadError from "../../error/CredentialLoadError";

const DEFAULT_PATH = 'revocation-credential.jsonld';
const DEFAULT_BRANCH = 'master';

const publish = ({token, owner, repo, branch, path, content, useGitHubPages}) => {
    const commitPath = path || DEFAULT_PATH;
    const commitBranch = branch || DEFAULT_BRANCH;

    const github = new GitHubApi({token});
    const repository = github.getRepo(owner, repo);
    const commitMessage = `Revocation update: ${new Date()}`;

    return new Promise((resolve, reject) => {
        return repository.writeFile(
            commitBranch,
            commitPath,
            JSON.stringify(content, null, 2),
            commitMessage,
            function (err) {
                if (!err) {
                    return resolve(_getGitHubUrl(owner, repo, commitBranch, commitPath, useGitHubPages));
                }
                reject(err);
            }
        );
    });
};

const validateGitHubOptions = gitHubOptions => {
    return new Promise((resolve, reject) => {
        if (!gitHubOptions) {
            return reject(new InvalidRevocationOptions('No options supplied for github config.'));
        }
        const {token, owner, repo} = gitHubOptions;
        if (!token || !owner || !repo) {
            const message = `Token, owner, and repo are all required. Received: (${token}, ${owner}, ${repo})`;
            return reject(new InvalidRevocationOptions(message));
        }

        const branch = gitHubOptions.branch || DEFAULT_BRANCH;
        const github = new GitHubApi({token});
        const repository = github.getRepo(owner, repo);

        return repository.getBranch(branch)
            .then(() => resolve(true))
            .catch(({response}) => {
                if (response.status === 401) {
                    return reject(new InvalidRevocationOptions("Invalid GitHub token."));
                }
                if (response.status === 404) {
                    const message = `Invalid branch ${branch} from ${owner}/${repo}. 
                    Github error: ${response.data.message}`;
                    return reject(new InvalidRevocationOptions(message));
                }
                const message = `Could not get repo branch ${branch} from ${owner}/${repo}. 
                Github error: ${response.data.message}`;
                return reject(new Error(message));
            });
    });
};

const getRevocationCredential = ({token, owner, repo, branch, path}) => {
    const credentialPath = path || DEFAULT_PATH;
    const credentialBranch = branch || DEFAULT_BRANCH;

    const github = new GitHubApi({token});
    const repository = github.getRepo(owner, repo);

    return repository.getContents(credentialBranch, credentialPath)
        .then(response => {
            return JSON.parse(Buffer.from(response.data.content, 'base64').toString('utf-8'));
        }).catch(err => {
            if (err instanceof SyntaxError) {
                const message = `Could not parse credential from (repo, branch, path): 
                (${repo}, ${credentialBranch}, ${path}). Originating error: ${err.message}`;
                throw new CredentialLoadError(message);
            }
            const message = `Could not load credential from (repo, branch, path):
            (${repo}, ${credentialBranch}, ${path}). Originating error: ${err.message}`;
            throw new CredentialLoadError(message);
        });
};

const _getGitHubUrl = (owner, repo, branch, path, useGitHubPages) => {
    if(useGitHubPages){
        return `https://${owner.toLowerCase()}.github.io/${repo.toLowerCase()}/${path}`;
    }
    return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
};


export default {publish, validateGitHubOptions, getRevocationCredential};
