package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/constraints"

	"github.com/go-sql-driver/mysql"
)

type message struct {
	id          uint32
	likes       uint32
	dislikes    uint32
	room        uint16
	x           uint16
	y           uint16
	word1       uint16
	word2       uint16
	template1   uint8
	template2   uint8
	conjunction uint8
	_           [3]uint8
}

func (m *message) scan(rs *sql.Rows) error {
	return rs.Scan(&m.id, &m.likes, &m.dislikes, &m.room, &m.x, &m.y, &m.word1, &m.word2, &m.template1, &m.template2, &m.conjunction)
}

type handler struct {
	handlerStmts
	db *sql.DB

	ipLimiter     Limiter
	loginLimiter  Limiter
	newUsrLimiter Limiter

	ipBlacklist Blacklist

	goodReqs CircularLog
	badReqs  CircularLog
	general  CircularLog

	table []byte

	tdiff time.Duration
}

func (h *handler) destroy() {
	h.closeStmts()
	h.goodReqs.Close()
	h.badReqs.Close()
	h.general.Close()
	if h.db != nil {
		h.db.Close()
	}
}

func newHandler(name string) (res *handler, err error) {
	var h handler
	h.db, err = sql.Open("mysql", name)
	if err != nil {
		return
	}

	err = h.prepStmts(h.db)
	if err != nil {
		return
	}

	var dbTimeRaw []byte
	err = h.db.QueryRow("SELECT NOW();").Scan(&dbTimeRaw)
	if err != nil {
		return
	}
	serverTime := time.Now()
	var dbTime time.Time
	dbTime, err = parseDateTime(dbTimeRaw, time.UTC)
	if err != nil {
		return
	}
	h.tdiff = dbTime.Sub(serverTime)

	err = h.general.Open(generalLogPath, generalLogSize)
	if err != nil {
		return
	}
	log.SetOutput(&h.general)
	err = h.badReqs.Open(badReqsLogPath, badReqsLogSize)
	if err != nil {
		return
	}
	err = h.goodReqs.Open(goodReqsLogPath, goodReqsLogSize)
	if err != nil {
		return
	}

	err = h.ipBlacklist.FromFile(blacklistPath)
	if err != nil {
		h.general.Log.Printf("failed to load blacklist: %v\n", err)
		err = nil
	}

	h.ipLimiter = Limiter{
		MaxEntries: 2048,
		Burst:      20,
		Reset:      20 * time.Second,
	}

	h.loginLimiter = Limiter{
		MaxEntries: 2048,
		Burst:      2,
		Reset:      30 * time.Second,
	}

	h.newUsrLimiter = Limiter{
		MaxEntries: 64,
		Burst:      2,
		Reset:      120 * time.Second,
	}

	var b bytes.Buffer
	for _, s := range templates {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	for _, s := range conjunctions {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	for _, s := range words {
		b.WriteByte('\n')
		b.WriteString(s)
	}
	b.WriteByte('\n')
	for _, s := range rooms {
		b.WriteByte('\n')
		b.WriteString(s)
	}
	h.table = b.Bytes()

	res = &h
	return
}

func getCredentials(r *http.Request) (string, string, bool) {
	query := r.URL.Query()
	name := query.Get("name")
	pass := query.Get("password")
	return name, pass, len(name) <= 64 && len(name) >= 3 && len(pass) <= 72 && len(pass) >= 8
}

func tokenToCookie(tok string, id uint32) *http.Cookie {
	return &http.Cookie{
		Name:   "token",
		Value:  tok + fmt.Sprintf("%v", id),
		Secure: true,
	}
}

var tokenLenError = errors.New("bad token length")
var unfinishedQuoteError = errors.New("unfinished quotation")

func tokenFromCookie(cookie string) (string, uint32, error) {
	const cookiePrefix = "token="
	fromTok := len(cookiePrefix) + 64
	toEnd := len(cookie)
	if toEnd < fromTok+1 {
		return "", 0, tokenLenError
	}
	toTok := len(cookiePrefix)
	if cookie[len(cookiePrefix)] == '"' {
		if toEnd < fromTok+1+len("\"\"") {
			return "", 0, tokenLenError
		}
		toEnd--
		if cookie[toEnd] != '"' {
			return "", 0, unfinishedQuoteError
		}
		fromTok++
		toTok++
	}
	id, err := strconv.ParseUint(cookie[fromTok:toEnd], 10, 32)
	return cookie[toTok:fromTok], uint32(id), err
}

func asUint[T constraints.Unsigned](s string) (T, error) {
	u64, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return T(0), err
	}
	if u64 > uint64(^T(0)) {
		return T(0), strconv.ErrRange
	}
	return T(u64), nil
}

// moderately evil hack
func qAs[T constraints.Unsigned](q *url.Values, s string, e *error) T {
	if *e != nil {
		return T(0)
	}
	res, err := asUint[T](q.Get(s))
	*e = err
	return res
}

func qAsDate(q *url.Values, s string, e *error) time.Time {
	if *e != nil {
		return time.Time{}
	}
	res, err := time.Parse(time.DateTime, q.Get(s))
	*e = err
	return res
}

func (h *handler) authenticateRequest(r *http.Request) (userid uint32, status int) {
	cookies := r.Header.Values("Cookie")
	if len(cookies) != 1 {
		return 0, http.StatusBadRequest
	}
	tok, id, err := tokenFromCookie(cookies[0])
	if err != nil {
		return 0, http.StatusBadRequest
	}
	var exists int
	err = h.getSession.QueryRow(id, tok).Scan(&exists)
	if err != nil {
		h.general.Log.Printf("failed session lookup: %v\n", err)
		return 0, http.StatusInternalServerError
	}
	if exists != 1 {
		return 0, http.StatusUnauthorized
	}
	return id, http.StatusOK
}

func sendMessages(rows *sql.Rows, dst http.ResponseWriter) {
	var msg message
	for safety := 0; safety < 5000; safety++ {
		// "Every call to Rows.Scan, even the first one,
		// must be preceded by a call to Rows.Next."
		if !rows.Next() {
			break
		}
		msg.scan(rows)
		err := binary.Write(dst, binary.LittleEndian, &msg)
		if err != nil {
			dst.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

var encodingOutOfBounds = errors.New("code does not exist")

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// I am very upset that there is no field in an http.Request that
	// corresponds to the IP. No, RemoteAddr doesn't count; it's for
	// logging, and may be a load balancer (though not for us, we don't have
	// one). I'm not going to check headers because clients can change them.
	// Following: bad code to work around this
	if len(r.RemoteAddr) > 20 {
		// likely ipv6
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	// trim port
	pos := strings.LastIndexByte(r.RemoteAddr, ':')
	if pos == -1 {
		pos = len(r.RemoteAddr)
	}
	trimmedIP := r.RemoteAddr[:pos]

	if h.ipBlacklist.Present(trimmedIP) {
		w.WriteHeader(http.StatusForbidden)
		h.general.Log.Printf("denied %v\n", r.RemoteAddr)
		return
	}

	if h.ipLimiter.Block(trimmedIP) {
		w.WriteHeader(http.StatusTooManyRequests)
		h.general.Log.Printf("limited %v\n", r.RemoteAddr)
		return
	}

	path := r.URL.EscapedPath()
	// NOTE: make sure we never have legitimate paths this long!
	if len(path) > 24 {
		// definitely someone looking for a vulnerability
		// one guy tried /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
		h.ipBlacklist.Insert(trimmedIP)
		h.general.Log.Printf("blacklisted %v due to suspicious query %v\n", trimmedIP, path)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	switch path {
	case "/query":
		// TODO clean up logic here
		query := r.URL.Query()
		var err error
		room := qAs[uint16](&query, "room", &err)
		ageStr := query.Get("age")
		age := time.Time{}
		if ageStr != "" && err == nil {
			age, err = time.Parse(time.DateTime, ageStr)
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var rows *sql.Rows
		rows, err = h.queryMessagesByRoom.Query(room, age)
		if rows != nil {
			// not sure what happens to rows if err != nil,
			// so here's the catch-all solution
			defer rows.Close()
		}
		if err != nil {
			h.general.Log.Printf("message query with room='%v' age='%v' failed\n", room, age)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sendMessages(rows, w)
	case "/mine":
		id, status := h.authenticateRequest(r)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		rows, err := h.queryMessagesByUsr.Query(id)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			h.general.Log.Printf("message query with userid='%v' failed\n", id)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sendMessages(rows, w)
	case "/login":
		name, pass, ok := getCredentials(r)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var id uint32
		buf := make([]byte, 60)
		err := h.queryUsr.QueryRow(name).Scan(&id, &buf)
		if err != nil {
			// TODO: figure out if it's actually our error
			// it's probably not though
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if h.loginLimiter.Block(name) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		err = bcrypt.CompareHashAndPassword(buf, []byte(pass))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		buf = buf[:48] // tokens are 48 bytes, so 64 when encoded base64
		rand.Read(buf)
		tok := base64.StdEncoding.EncodeToString(buf)
		expire := time.Now().Add(h.tdiff + time.Hour * 1)
		_, err = h.createSession.Exec(id, tok, expire)
		if err != nil {
			h.general.Log.Printf("create session failed: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, tokenToCookie(tok, id))
	case "/register":
		// TODO if current user count > 1000 return http.StatusInsufficientStorage
		if h.newUsrLimiter.Block(trimmedIP) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		name, pass, ok := getCredentials(r)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		asBytes := []byte(pass)
		hash, err := bcrypt.GenerateFromPassword(asBytes, 10)
		if err != nil || len(hash) != 60 {
			h.general.Log.Printf("hash gen failed on %v: %v\n", asBytes, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// we should clear pass and asBytes, but idk how
		// not to mention it exists in the query map too...
		// this is the one time C is more secure, since fine memory
		// control is required here
		_, err = h.createUsr.Exec(name, hash)
		if err != nil {
			casted, ok := err.(*mysql.MySQLError)
			if ok && casted.Number == 1062 {
				// someone has that name already
				w.WriteHeader(http.StatusConflict)
			} else {
				h.general.Log.Printf("create user failed: %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
		h.general.Log.Printf("new user %v\n", name)
	case "/write":
		query := r.URL.Query()
		var err error
		no := func(cond bool) {
			if cond {
				err = encodingOutOfBounds
			}
		}
		room := qAs[uint16](&query, "room", &err)
		no(int(room) >= len(rooms))
		x := qAs[uint16](&query, "x", &err)
		y := qAs[uint16](&query, "y", &err)
		t1 := qAs[uint8](&query, "t1", &err)
		no(int(t1) >= len(templates))
		w1 := qAs[uint16](&query, "w1", &err)
		no(int(w1) >= len(words))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conjunctionStr := query.Get("c")
		var w2 uint16
		var c, t2 uint8
		if conjunctionStr == "" {
			c = ^uint8(0)
		} else {
			c, err = asUint[uint8](conjunctionStr)
			no(int(c) >= len(conjunctions))
			w2 = qAs[uint16](&query, "w2", &err)
			no(int(w2) >= len(words))
			t2 = qAs[uint8](&query, "t2", &err)
			no(int(t2) >= len(templates))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		id, status := h.authenticateRequest(r)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		var msgCount int
		err = h.countMessagesFromUsr.QueryRow(id).Scan(&msgCount)
		if err != nil {
			h.general.Log.Printf("count messages failed: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if msgCount >= maxMessagesPerUser {
			w.WriteHeader(http.StatusConflict)
			return
		}
		_, err = h.createMessage.Exec(id, room, x, y, t1, w1, c, t2, w2)
		if err != nil {
			h.general.Log.Printf("message write failed: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "/erase":
		query := r.URL.Query()
		msgId, err := asUint[uint32](query.Get("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		usrId, status := h.authenticateRequest(r)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		res, err := h.eraseMessage.Exec(msgId, usrId)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cnt, err := res.RowsAffected()
		if err != nil || cnt != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	case "/vote":
		// TODO vote on a message
		//tx, err := h.db.Begin()
		//tx.Commit()
		w.WriteHeader(http.StatusNotImplemented)
	case "/table":
		w.Write(h.table)
	case "/version":
		err := binary.Write(w, binary.LittleEndian, version)
		if err != nil {
			h.general.Log.Printf("but how!? %v\n")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "/robots.txt":
		w.Write([]byte("User-agent: *\nDisallow: /"))
	case "/favicon.ico":
		// silly client this is not that kind of server
		w.WriteHeader(http.StatusTeapot)
		return
	default:
		h.badReqs.Log.Printf("%v %v %v %v\n", r.RemoteAddr, r.Method, path, r.Header)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	h.goodReqs.Log.Printf("%v %v %v %v\n", r.RemoteAddr, r.Method, path, r.Header)
}
