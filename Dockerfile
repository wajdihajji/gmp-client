FROM uisautomation/python:3.8-alpine

# set the working directory in the container
WORKDIR /usr/src/app

# copy the dependencies file to the working directory
COPY requirements.txt .

# install dependencies
RUN pip install -r requirements.txt

# Add user gvm to be used for gvm-tools commands
RUN useradd -m gvm

# Bundle app source
COPY . /usr/src/app

CMD ["python", "-u", "src"]
