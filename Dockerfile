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

RUN echo ${NB_UID} ${NB_USER}
USER root

RUN adduser --disabled-password \
    --gecos "Default user" \
    --uid ${NB_UID} \
    ${NB_USER}

RUN chown ${NB_USER} /run/postgresql /usr/local/share/jupyter/kernels/pyspark3/kernel.json \
  && chown -R ${NB_USER}:${NB_USER} /opt/helk

WORKDIR ${HOME}

USER ${NB_USER}