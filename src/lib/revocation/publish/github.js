import GitHubApi from 'github-api';
import Promise from 'promise';
import InvalidGitHubOptions from "../../error/InvalidGitHubOptions";

const DEFAULT_PATH = 'revocation-credential.jsonld';
const DEFAULT_BRANCH = 'master';

const publish = ({token, owner, repo, branch, path, content}) => {
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
                    return resolve(_getGitHubUrl(owner, repo, commitPath));
                }
                reject(err);
            }
        );
    });
};

const validateGitHubOptions = gitHubOptions => {
    return new Promise((resolve, reject) => {
        if (!gitHubOptions) {
            return reject(new InvalidGitHubOptions('No options supplied for github config.'));
        }
        const {token, owner, repo} = gitHubOptions;
        if (!token || !owner || !repo) {
            const message = `Token, owner, and repo are all required. Received: (${token}, ${owner}, ${repo})`;
            return reject(new InvalidGitHubOptions(message));
        }

        const branch = gitHubOptions.branch || 'master';
        const github = new GitHubApi({token});
        const repository = github.getRepo(owner, repo);

        return repository.getBranch(branch)
            .then(() => resolve(true))
            .catch(({response}) => {
                if (response.status === 401) {
                    return reject(new InvalidGitHubOptions("Invalid GitHub token."));
                }
                if (response.status === 404) {
                    const message = `Invalid branch ${branch} from ${owner}/${repo}. 
                    Github error: ${response.data.message}`;
                    return reject(new InvalidGitHubOptions(message));
                }
                const message = `Could not get repo branch ${branch} from ${owner}/${repo}. 
                Github error: ${response.data.message}`;
                return reject(new Error(message));
            });
    });
};

const _getGitHubUrl = (owner, repo, path) => {
    return `https://${owner.toLowerCase()}.github.io/${repo.toLowerCase()}/${path}`;
};


export default {publish, validateGitHubOptions};

