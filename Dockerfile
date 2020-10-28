FROM node:12.19.0

# File Author / Maintainer
LABEL authors="Scott Malley <smalley@sphereon.com>"

# Update & install required packages
RUN apt-get install bash git

# Install app dependencies
COPY package.json /www/package.json
RUN cd /www; npm install

# Copy app source
COPY . /www

# Set work directory to /www
WORKDIR /www

# set your port
ENV PORT 8080

# expose the port to outside world
EXPOSE  8080

# start command as per package.json
CMD ["npm", "start"]
