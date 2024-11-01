## Project Soapstone
A backend for orange guidance soapstone messages, made with Hollow Knight in mind.

Being an open-source project means that you can also run my server of questionable quality! However, please don't do this publicly without talking to me first. The point of this whole project is to see funny messages in game, and if many people run the project, then there will be fewer messages per host. If the current hosting is insufficient, I'd be happy to work something out with you. I'm not opposed to someone else hosting it.

## API
Please direct your traffic to 128.9.29.8:443\
The certificate is self-signed for my convenience.

### Rate limiting
Each IP is limited to 20 requests per minute. Any request you make counts toward this, even if the request failed. Making requests faster than this will result in a status of 429 being returned. Certain requests are rate limited further, but legitimate clients should not worry about this.

The numbers I chose with regards to rate limiting are completely arbitrary and possible slightly too low to be easy to use. I may make the server less strict in the future, should the need arise.

### Message format
Some requests return a stream of messages in the body, which are defined as follows:
```
00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27
|---------| |---------| |---------| |---| |---| |---| |---| |---| || || || |------|
    id^        likes^    dislikes^     |    x^    y^     |     |   |  |  |  ^padding
                                   room^            word1^     |   |  |  ^conjunction
                                                          word2^   |  ^template2
                                                                   ^template1
```
* Padding bytes 25 to 27 are also sent. Their value should be 0 and ignored.
* All values are little-endian and unsigned.
* A value of 255 for the conjunction means that the message only has one part (so ignore conjunction, template2, and word2 for that message).

### Requests
Please note! Certain numbers do not yet have meaning. Parameter room should be a number to represent an in-game room, and parameters x and y should represent a position within this room. Since I don't know how Hollow Knight works, until someone defines them to me, they're pretty meaningless.

Numbers are sent as numbers, not strings. Always little-endian. This means less parsing for you and less formatting for me: win-win!

Arguments are passed from the client to the server by path parameters. This is because it's really easy to test out stuff by typing the url in a browser. This may change for certain requests in the future.

All requests can return a generic 400 if a required parameter, header, or body is omitted. When it would be useful to the client, other 4xx errors are returned.

Clients should act accordingly on any 4xx error the server returns. 400 means you really messed up, and probably need to change the client's code.

All requests can return a 5xx error. Hopefully they don't though.

#### GET /query
* Path parameters:
    * room: the numeric identity of the room the messages are part of
    * age: (optional) a datetime that all resulting messages must be younger than\
* Response:
    * 200: the body will contains a stream of messages
    * 400: the age could not be parsed as a datetime

#### GET /login
This request is rate limited to 2 requests per 30 seconds by given name.
* Path parameters:
    * name: a 3 to 64 character username
    * password: an 8 to 72 character password
* Response:
    * 200: a Set-Cookie header is sent with a value representing your new session token
    * 400: the name or password does not meet the length restrictions
    * 401: the login attempt failed

#### GET /register
This request is rate limited to 2 requests per 2 minutes by IP.
* Path parameters:
    * name: a 3 to 64 character username
    * password: an 8 to 72 character password
* Response:
    * 200: no further response; you may now log in
    * 400: the name or password does not meet the length restrictions
    * 409: the name is already in use

#### GET /write
NOTE: this request may eventually change to POST /write with the message in the body
* Path parameters:
    * room: the numeric identity of the room the messages are part of
    * x: the horizontal position within the room the message should appear at
    * y: the vertical position within the room the message should appear at
    * t1: the numeric identity of the primary template
    * w1: the numeric identity of the primary word
    * c: (optional) the numeric identity of the conjunction
    * t2: (conditionally required) the numeric identity of the secondary template; only present if c is
    * w2: (conditionally required) the numeric identity of the secondary word; only present if c is
* Response:
    * 200: no further response; message posted successfully
    * 400: the message is incomplete, contains invalid identifiers, or an identifier could not be parsed
    * 401: the request was made without a token, or with an expired or invalid token; try logging in

#### GET /erase
NOTE: this request may eventually change to POST /erase with the id in the body
* Path parameters:
    * id: the numeric message identifier to delete
* Response:
    * 200: no further response; message removed successfully
    * 400: the requested message to be deleted is not yours
    * 401: the request was made without a token, or with an expired or invalid token; try logging in

#### GET /mine
NOTE: this request may eventually change to POST /mine with the id in the body
* Response:
    * 200: the body will contains a stream of your messages
    * 401: the request was made without a token, or with an expired or invalid token; try logging in

#### GET /version
* Response:
    * 200: the body will contains a little endian unsigned 32 bit integer representing the version of the server

#### GET /table
This table can be used to determine the numeric identifier for templates, conjunctions, and words. There are three sections to the returned body. The first section contains newline separated templates. The second section contains newline separated conjunctions. The third section contains newline separated words. Each section is separated by an empty line. The identifier for the nth item in a section is n.
* Response:
    * 200: the body will contain newline separated strings

#### GET /vote
TODO
* Response:
    * 501: I'm working on it!

## A note for wise guys
By design this server is quick to reach its maximum willing work capacity. The computer it's running on *could* handle a whole lot more traffic, but it does other things too, so this program is very considerate in terms of resource consumption. This means it's almost trivial to deny legitimate users service if you attack it. So please don't, not for the server's sake (which will simply refuse to work hard), but for other clients' sake.

I'll implement an IP blacklist if it comes to it.
