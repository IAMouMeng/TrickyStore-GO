package alias

import "sync"

var Store = NewAliasStore()

type aliasKey struct {
	UID       uint32
	AliasName string
}

type CertEntry struct {
	Leaf     []byte
	Keychain []byte
}

type StoreAlias struct {
	mu    sync.RWMutex
	items map[aliasKey]CertEntry
}

func NewAliasStore() *StoreAlias {
	return &StoreAlias{
		items: make(map[aliasKey]CertEntry),
	}
}

func (a *StoreAlias) StoreLeaf(uid uint32, aliasName string, leaf []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := aliasKey{UID: uid, AliasName: aliasName}
	entry := a.items[key]
	entry.Leaf = make([]byte, len(leaf))
	copy(entry.Leaf, leaf)
	a.items[key] = entry
}

func (a *StoreAlias) StoreKeychain(uid uint32, aliasName string, keychain []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := aliasKey{UID: uid, AliasName: aliasName}
	entry := a.items[key]
	entry.Keychain = make([]byte, len(keychain))
	copy(entry.Keychain, keychain)
	a.items[key] = entry
}

func (a *StoreAlias) GetLeaf(uid uint32, aliasName string) ([]byte, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	entry, ok := a.items[aliasKey{UID: uid, AliasName: aliasName}]
	if !ok || entry.Leaf == nil {
		return nil, false
	}
	return entry.Leaf, true
}

func (a *StoreAlias) GetKeychain(uid uint32, aliasName string) ([]byte, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	entry, ok := a.items[aliasKey{UID: uid, AliasName: aliasName}]
	if !ok || entry.Keychain == nil {
		return nil, false
	}
	return entry.Keychain, true
}

func (a *StoreAlias) Delete(uid uint32, aliasName string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.items, aliasKey{UID: uid, AliasName: aliasName})
}
