# RubyCAS-Server

## Beyond Z Customizations

The file lib/casserver/views/layout.erb has the login layout html. This is based on the main site, but it is modified, so must be maintained separately.

The public/ folder has image and css assets brought off the main site. These are simply downloaded from the production site and renamed - to do this, load the join.bebraven.org site in your browser, view source and find the link rel=styleshet near the top. Download that file and save it in here as public/beyondz.css. They do NOT need to be maintained separately at this time. Currently required are the logo, favicon, and stylesheet.

The file lib/beyondz.rb holds our authenticator. It uses a cooperative check_credentials http api on the public site to check against the main database. It is configured via config.yml for server (string), port (integer), ssl (boolean), and allow_self_signed (boolean) to know where to connect. The default ssl options is production-ready - it will verify certificates and use SSL. For development purposes, you may turn these options off with ssl: false.

## End user flow

The end user should always go to the service they want to use (portal.bebraven.org for example). The service then redirects them to the single sign on server, with a service parameter telling it to redirect them back once login is complete.

user goes to canvas -> canvas sends them to sso -> sso sends back to canvas

On the backend, the SSO server talks to the public site server and the service (canvas) server talks to the SSO server to validate login tickets. This should be SSL secured in production so the sso and canvas servers both need working client certificates, and the sso and public site servers need to be running https.

The user master record is stored on the public site. User records also need to exist on the service - so a bz.org and canvas user need to exist with the same email address for the login to succeed end to end.

## Copyright

Portions contributed by Matt Zukowski are copyright (c) 2011 Urbacon Ltd.
Other portions are copyright of their respective authors.

## Authors

See https://github.com/rubycas/rubycas-server/graphs/contributors

## Installation

Example with mysql database:

1. `git clone git://github.com/rubycas/rubycas-server.git`
2. `cd rubycas-server`
3. `cp config/config.example.yml config.yml`
4. Customize your server by modifying the `config.yml` file. It is well commented but make sure that you take care of the following:
    1. Change the database driver to `mysql2`
    2. Configure at least one authenticator
    3. You might want to change `log.file` to something local, so that you don't need root. For example just `casserver.log`
    4. You might also want to disable SSL for now by commenting out the `ssl_cert` line and changing the port to something like `8888`
5. Create the database (i.e. `mysqladmin -u root create casserver` or whatever you have in `config.yml`)
6. Modify the existing Gemfile by adding drivers for your database server. For example, if you configured `mysql2` in config.yml, add this to the Gemfile: `gem "mysql2"`
7. Run `bundle install`
8. `bundle exec rubycas-server -c config.yml`

Your RubyCAS-Server should now be running. Once you've confirmed that everything looks good, try switching to a [Passenger](http://www.modrails.com/) deployment. You should be able to point Apache (or whatever) to the `rubycas-server/public` directory, and everything should just work.

Some more info is available at the [RubyCAS-Server Wiki](https://github.com/rubycas/rubycas-server/wiki).

If you have questions, try the [RubyCAS Google Group](https://groups.google.com/forum/?fromgroups#!forum/rubycas-server) or #rubycas on [freenode](http://freenode.net).

## License

RubyCAS-Server is licensed for use under the terms of the MIT License.
See the LICENSE file bundled with the official RubyCAS-Server distribution for details.

## Running in a local development environment using Docker

Edit `/etc/hosts` and add these values.
```Shell
127.0.0.1     joinweb
127.0.0.1     ssoweb
127.0.0.1     canvasweb
```
Bring up the Join server locally b/c this Docker container is configured
to point at it for the user database / credentials. Do this by following
the instructions [here](https://github.com/beyond-z/beyondz-platform#docker-setup)

Then, from your application root just run:
```Shell
docker-compose up -d
```
When complete, the app will be available at: `http://ssoweb:3002`

Note: the build will have a couple errors you can ignore. They don't
seem to impact the functioning of the app. Just ignore:
```Shell
fatal: Not a git repository (or any of the parent directories): .git
app/bin/rubycas-server maybe `gem pristine rubycas-server` will fix it?
```

Some things to keep in mind with Docker:
* If there are build errors, run `docker-compose logs` to see what they
  are.
* The environment variables come from `docker-compose.yml` They are
  injected into the container using `envsubst` in the
`./docker-compose/scripts/docker_compose_run.sh` script.
* If you change environment variables, rebuild to have them picked up by
  running `./docker-compose/scripts/rebuild.sh
* There are more scripts in `./docker-compose/scripts` to help you work
  with the container(s).
* If you change a file on the host (aka outside the container) it
does not take effect inside the container. This application is rarely
changed, so we don't mount a volume to allow files to be seamlessly
changed inside and outside. To have a change take effect run
`docker-compose/scripts/rebuild.sh`
* Lastly, and this is IMPORTANT, the version of Ruby that we run on
  production is 1.9.3. However, getting Docker building with that
version has proven troublesome, so the Docker dev env runs Ruby 2.1. For
that reason, DO NOT check-in the `Gemfile.lock` built on your local dev
env or the update the `rubycas-server.gemspec`. If we have to rebuild
gems on prod, we'll have to bite the bullet and upgrade the server (or
consolidate the SSO server into the Join server
