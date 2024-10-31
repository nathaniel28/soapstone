// This file was generated by storegen.py
// Do not edit this manually

package main

import "database/sql"

type handlerStmts struct {
	createUsr *sql.Stmt
	queryUsr *sql.Stmt
	createMessage *sql.Stmt
	queryMessagesByRoom *sql.Stmt
	queryMessagesByUsr *sql.Stmt
	countMessagesFromUsr *sql.Stmt
	createSession *sql.Stmt
	expireOldSessions *sql.Stmt
	getSession *sql.Stmt
}

func (h *handlerStmts) closeStmts() {
	if h.createUsr != nil {
		h.createUsr.Close()
	}
	if h.queryUsr != nil {
		h.queryUsr.Close()
	}
	if h.createMessage != nil {
		h.createMessage.Close()
	}
	if h.queryMessagesByRoom != nil {
		h.queryMessagesByRoom.Close()
	}
	if h.queryMessagesByUsr != nil {
		h.queryMessagesByUsr.Close()
	}
	if h.countMessagesFromUsr != nil {
		h.countMessagesFromUsr.Close()
	}
	if h.createSession != nil {
		h.createSession.Close()
	}
	if h.expireOldSessions != nil {
		h.expireOldSessions.Close()
	}
	if h.getSession != nil {
		h.getSession.Close()
	}
}

func (h *handlerStmts) prepStmts(db *sql.DB) (err error) {
	defer func() {
		if err != nil {
			h.closeStmts()
		}
	}()
	h.createUsr, err = db.Prepare("INSERT INTO users (name, hash) VALUES (?, ?);")
	if err != nil {
		return
	}
	h.queryUsr, err = db.Prepare("SELECT id, hash FROM users WHERE name = ?;")
	if err != nil {
		return
	}
	h.createMessage, err = db.Prepare("INSERT INTO messages (userid, room, x, y, template1, word1, conjunction, template2, word2) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);")
	if err != nil {
		return
	}
	h.queryMessagesByRoom, err = db.Prepare("SELECT id, likes, dislikes, room, x, y, word1, word2, template1, template2, conjunction FROM messages WHERE room = ? AND birth >= ? LIMIT 4096;")
	if err != nil {
		return
	}
	h.queryMessagesByUsr, err = db.Prepare("SELECT id, likes, dislikes, room, x, y, word1, word2, template1, template2, conjunction FROM messages WHERE userid = ?;")
	if err != nil {
		return
	}
	h.countMessagesFromUsr, err = db.Prepare("SELECT COUNT(*) FROM messages WHERE userid = ?;")
	if err != nil {
		return
	}
	h.createSession, err = db.Prepare("INSERT INTO sessions (userid, token, expire) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE token = VALUES (token), expire = VALUES (expire);")
	if err != nil {
		return
	}
	h.expireOldSessions, err = db.Prepare("DELETE FROM sessions WHERE expire < NOW();")
	if err != nil {
		return
	}
	h.getSession, err = db.Prepare("SELECT EXISTS(SELECT 1 FROM sessions WHERE userid = ? AND token = ?);")
	if err != nil {
		return
	}
	return
}
