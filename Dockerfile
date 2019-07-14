# ThreatHunter Playbook script: Jupyter Environment Dockerfile
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: GPL-3.0

FROM cyb3rward0g/jupyter-hunt:0.0.2
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
    ${NB_USER} \
    && apt-get install -y --no-install-recommends git \
    # ********* Mordor Project Files *********
    && git clone https://github.com/Cyb3rWard0g/mordor.git ${HOME}/mordor \
    && cd ${HOME}/mordor/small_datasets/ \
    && find . -type f -name "*.tar.gz" -print0 | sudo xargs -0 -I{} tar xf {} -C .

# ********* ThreatHunter-Playbook Files *********
COPY . ${HOME}

RUN chown ${NB_USER} /run/postgresql /usr/local/share/jupyter/kernels/pyspark3/kernel.json \
  && chown -R ${NB_USER}:${NB_USER} ${HOME} /opt/helk

WORKDIR ${HOME}

USER ${NB_USER}