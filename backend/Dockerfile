FROM ruby:3.2.1

RUN apt-get update -qq && apt-get install -y build-essential libpq-dev nodejs

RUN mkdir /backend
WORKDIR /backend

ADD Gemfile /backend/Gemfile
ADD Gemfile.lock /backend/Gemfile.lock
RUN bundle install

# Japanese
RUN apt-get install -y locales task-japanese && \
    locale-gen ja_JP.UTF-8 && \
    localedef -f UTF-8 -i ja_JP ja_JP
ENV LANG ja_JP.UTF-8

# Japanese font
RUN apt -qqy --no-install-recommends install -y fonts-takao-gothic fonts-takao-mincho && \
    dpkg-reconfigure --frontend noninteractive locales && \
    fc-cache -fv
