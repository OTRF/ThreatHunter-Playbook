#!/bin/bash

# ThreatHunter-Playbook script: playbook-setup.sh
# ThreatHunter-Playbook script description: Downloads Latest ThreatHunter-playbook and Mordor and decompresses small datasets
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: GPL-3.0

# *********** Creating Kibana index-patterns ***************
declare -a github_repos=("mordor" "ThreatHunter-Playbook")

echo "[THP-SETUP-INFO] Checking if repos need to be updated..."
for repo in ${!github_repos[@]}; do
    echo "[+] Checking ${repo}"
    cd ${HOME}/${repo}
    # ******* Check if local repo needs update *************
    echo "[+++] Fetch updates for remote repo.."
    git remote update

    # Reference: https://stackoverflow.com/a/3278427
    echo "[++] Checking to see if local Mordor repo is up to date or not.."
    UPSTREAM=${1:-'@{u}'}
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse "$UPSTREAM")
    BASE=$(git merge-base @ "$UPSTREAM")

    if [[ $LOCAL == $REMOTE ]]; then
        echo "[+++] Local repo is up-to-date.."
        if [[ $${repo} == "mordor" ]]; then
            if ls ../datasets/ | grep -v '*.json' >/dev/null 2>&1; then
                echo "[++++++] Datasets folder already has decompressed mordor files.."
            else
                echo "[++++++] Datasets folder is empty.."
                find small_datasets/ -type f -name "*.tar.gz" -print0 | sudo xargs -0 -I{} tar xf {} -C ../datasets/
            fi
            exit 1
        fi
    elif [ $LOCAL = $BASE ]; then
        echo "[++++++] Local repo needs to be updated. Updating local repo.."
        git pull
        if [[ $${repo} == "mordor" ]]; then
            find ../datasets/ -type f -name '*.json' -delete
            find small_datasets/ -type f -name "*.tar.gz" -print0 | sudo xargs -0 -I{} tar xf {} -C ../datasets/
        fi
        exit 1
    elif [ $REMOTE = $BASE ]; then
        echo "[++++++] Need to push"
        exit 1
    else
        echo "[++++++] Diverged"
        exit 1
    fi
done

echo "[THP-SETUP-INFO] Starting ThreatHunter-Playbook server.."
exec "$@"




