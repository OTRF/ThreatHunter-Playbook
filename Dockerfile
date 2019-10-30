# ThreatHunter Playbook script: Jupyter Environment Dockerfile
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: GPL-3.0

FROM cyb3rward0g/jupyter-pyspark:0.0.2
LABEL maintainer="Roberto Rodriguez @Cyb3rWard0g"
LABEL description="Dockerfile ThreatHunter Playbook Project."

ARG NB_USER
ARG NB_UID
ENV NB_USER jovyan
ENV NB_UID 1000
ENV HOME /home/${NB_USER}

USER root

RUN adduser --disabled-password \
    --gecos "Default user" \
    --uid ${NB_UID} \
    ${NB_USER}

USER ${NB_USER}
    # ********* Install OpenHunt Library *****************
RUN python3 -m pip install openhunt==1.6.4 pyarrow==0.14.1 --user \
    # ********* Download and decompress mordor datasets *****************
    && git clone https://github.com/hunters-forge/mordor.git ${HOME}/mordor \
    && cd ${HOME}/mordor/small_datasets/ \
    && find . -type f -name "*.tar.gz" -print0 | xargs -0 -I{} tar xf {} -C .

COPY playbooks ${HOME}/playbooks

USER root

RUN chown ${NB_USER} /usr/local/share/jupyter/kernels/pyspark3/kernel.json \
    && cd ${HOME}/playbooks/ \
    && find . -type f -name "*.ipynb" -exec cp -n {} ${HOME}/ \; \
    && chown -R ${NB_USER}:${NB_USER} ${HOME} ${JUPYTER_DIR}

WORKDIR ${HOME}

USER ${NB_USER}