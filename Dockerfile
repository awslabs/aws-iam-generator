FROM python:3-alpine

VOLUME /iam_generator
WORKDIR /iam_generator

ADD bin /iam_generator/bin
ADD build.py /iam_generator
ADD requirements.txt /iam_generator
ADD entry.sh /iam_generator

RUN pip3 install -r requirements.txt

ENTRYPOINT ["/iam_generator/entry.sh"]
CMD ["--help"]
