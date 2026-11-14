// Package storetest holds conformance tests every store.Store
// implementation must pass.
package storetest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/store"
)

// Run runs all conformance tests. newStore must return an empty store.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	tests := map[string]func(*testing.T, store.Store){
		"Admins":         testAdmins,
		"Crawlers":       testCrawlers,
		"Nonces":         testNonces,
		"JobDelivery":    testJobDelivery,
		"SubmitResult":   testSubmitResult,
		"SubmitExpired":  testSubmitExpired,
		"SubmitOrdering": testSubmitOrdering,
		"Audit":          testAudit,
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) { fn(t, newStore(t)) })
	}
}

var t0 = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func addCrawler(t *testing.T, s store.Store, id string) store.Crawler {
	t.Helper()
	secret, _ := protocol.NewKey()
	c := store.Crawler{ID: id, Secret: secret, Allow: []string{"127.0.0.1/32"}, MaxHosts: 1, Enabled: true, CreatedAt: t0}
	mustNoErr(t, s.CreateCrawler(context.Background(), c))
	return c
}

func addJob(t *testing.T, s store.Store, crawlerID string, created time.Time, ttl time.Duration) store.Job {
	t.Helper()
	id, _ := protocol.NewID()
	token, _ := protocol.NewKey()
	j := store.Job{
		ID: id, CrawlerID: crawlerID, Targets: []string{"127.0.0.1/32"}, Ports: []int{22, 80},
		MaxHosts: 1, TimeoutMs: 500, ResultToken: token, Status: store.JobPending, CreatedBy: "admin",
		CreatedAt: created, ExpiresAt: created.Add(ttl),
	}
	mustNoErr(t, s.CreateJob(context.Background(), j))
	return j
}

func testAdmins(t *testing.T, s store.Store) {
	ctx := context.Background()
	_, err := s.AdminByUsername(ctx, "admin")
	wantErr(t, err, store.ErrNotFound)

	mustNoErr(t, s.SetAdmin(ctx, "admin", "hash1"))
	a, err := s.AdminByUsername(ctx, "admin")
	mustNoErr(t, err)
	mustNoErr(t, s.SetAdmin(ctx, "admin", "hash2"))
	b, err := s.AdminByUsername(ctx, "admin")
	mustNoErr(t, err)
	if b.ID != a.ID || b.PasswordHash != "hash2" {
		t.Errorf("SetAdmin must update in place: %+v -> %+v", a, b)
	}

	token := []byte("0123456789abcdef0123456789abcdef")
	mustNoErr(t, s.CreateSession(ctx, token, a.ID, t0.Add(time.Hour)))
	got, err := s.SessionAdmin(ctx, token, t0)
	mustNoErr(t, err)
	if got.Username != "admin" {
		t.Errorf("session admin = %+v", got)
	}
	_, err = s.SessionAdmin(ctx, token, t0.Add(time.Hour))
	wantErr(t, err, store.ErrNotFound)
	mustNoErr(t, s.DeleteSession(ctx, token))
	_, err = s.SessionAdmin(ctx, token, t0)
	wantErr(t, err, store.ErrNotFound)
}

func testCrawlers(t *testing.T, s store.Store) {
	ctx := context.Background()
	c := addCrawler(t, s, "lab-2")
	addCrawler(t, s, "lab-1")
	wantErr(t, s.CreateCrawler(ctx, c), store.ErrExists)

	got, err := s.Crawler(ctx, "lab-2")
	mustNoErr(t, err)
	if string(got.Secret) != string(c.Secret) || len(got.Allow) != 1 || got.MaxHosts != 1 || !got.Enabled || got.LastSeenAt != nil {
		t.Errorf("crawler = %+v", got)
	}
	_, err = s.Crawler(ctx, "nope")
	wantErr(t, err, store.ErrNotFound)

	mustNoErr(t, s.TouchCrawler(ctx, "lab-2", t0.Add(time.Minute)))
	got, _ = s.Crawler(ctx, "lab-2")
	if got.LastSeenAt == nil || !got.LastSeenAt.Equal(t0.Add(time.Minute)) {
		t.Errorf("last seen = %v", got.LastSeenAt)
	}
	wantErr(t, s.TouchCrawler(ctx, "nope", t0), store.ErrNotFound)

	list, err := s.ListCrawlers(ctx)
	mustNoErr(t, err)
	if len(list) != 2 || list[0].ID != "lab-1" || list[1].ID != "lab-2" {
		t.Errorf("list = %+v", list)
	}
}

func testNonces(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	addCrawler(t, s, "lab-2")
	mustNoErr(t, s.UseNonce(ctx, "lab-1", "nonce-0000000001", t0))
	wantErr(t, s.UseNonce(ctx, "lab-1", "nonce-0000000001", t0), store.ErrReplay)
	mustNoErr(t, s.UseNonce(ctx, "lab-2", "nonce-0000000001", t0))
	mustNoErr(t, s.PurgeNonces(ctx, t0.Add(time.Second)))
	mustNoErr(t, s.UseNonce(ctx, "lab-1", "nonce-0000000001", t0.Add(time.Hour)))
}

func testJobDelivery(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	addCrawler(t, s, "lab-2")

	_, ok, err := s.NextJob(ctx, "lab-1", t0)
	mustNoErr(t, err)
	if ok {
		t.Fatal("no job expected")
	}

	expired := addJob(t, s, "lab-1", t0.Add(-time.Hour), time.Minute)
	second := addJob(t, s, "lab-1", t0.Add(2*time.Second), 5*time.Minute)
	first := addJob(t, s, "lab-1", t0.Add(time.Second), 5*time.Minute)
	other := addJob(t, s, "lab-2", t0, 5*time.Minute)

	now := t0.Add(time.Minute)
	for _, want := range []store.Job{first, second} {
		j, ok, err := s.NextJob(ctx, "lab-1", now)
		mustNoErr(t, err)
		if !ok || j.ID != want.ID {
			t.Fatalf("NextJob = %v %v, want %s", j.ID, ok, want.ID)
		}
		if j.Status != store.JobDelivered || j.DeliveredAt == nil || !j.DeliveredAt.Equal(now) {
			t.Errorf("delivered job = %+v", j)
		}
		if string(j.ResultToken) != string(want.ResultToken) || len(j.Ports) != 2 || j.Ports[1] != 80 {
			t.Errorf("job fields not preserved: %+v", j)
		}
	}
	if _, ok, _ := s.NextJob(ctx, "lab-1", now); ok {
		t.Error("expired or delivered jobs must not be handed out")
	}
	if j, _ := s.Job(ctx, expired.ID); j.Status != store.JobPending {
		t.Errorf("expired job status = %s", j.Status)
	}
	if j, ok, _ := s.NextJob(ctx, "lab-2", now); !ok || j.ID != other.ID {
		t.Error("lab-2 must get its own job")
	}

	_, err = s.Job(ctx, "00000000-0000-4000-8000-000000000000")
	wantErr(t, err, store.ErrNotFound)
	_, err = s.Job(ctx, "not-a-uuid")
	wantErr(t, err, store.ErrNotFound)

	list, err := s.ListJobs(ctx, 2)
	mustNoErr(t, err)
	if len(list) != 2 || list[0].ID != second.ID {
		t.Errorf("ListJobs newest first, limited: %+v", list)
	}

	j := addJob(t, s, "lab-1", t0, time.Minute)
	j.CrawlerID = "nope"
	j.ID, _ = protocol.NewID()
	wantErr(t, s.CreateJob(ctx, j), store.ErrNotFound)
}

func submission(j store.Job, crawlerID, nonce string, now time.Time, valid bool) store.Submission {
	body := []byte(`{"job_id":"` + j.ID + `","networks":[]}`)
	sum := sha256.Sum256(body)
	return store.Submission{
		CrawlerID: crawlerID, JobID: j.ID, Nonce: nonce, Now: now,
		Verify:     func(token []byte) bool { return valid && string(token) == string(j.ResultToken) },
		Body:       body,
		BodySHA256: sum[:],
	}
}

func testSubmitResult(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	addCrawler(t, s, "lab-2")
	j := addJob(t, s, "lab-1", t0, 5*time.Minute)
	now := t0.Add(time.Minute)

	// Not delivered yet.
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-a-000000001", now, true)), store.ErrForbidden)
	if _, ok, _ := s.NextJob(ctx, "lab-1", now); !ok {
		t.Fatal("job not delivered")
	}
	unknown := j
	unknown.ID, _ = protocol.NewID()
	wantErr(t, s.SubmitResult(ctx, submission(unknown, "lab-1", "nonce-a-000000002", now, true)), store.ErrUnauthorized)
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-2", "nonce-a-000000003", now, true)), store.ErrForbidden)
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-a-000000004", now, false)), store.ErrUnauthorized)

	sub := submission(j, "lab-1", "nonce-a-000000005", now, true)
	mustNoErr(t, s.SubmitResult(ctx, sub))
	got, err := s.Job(ctx, j.ID)
	mustNoErr(t, err)
	if got.Status != store.JobCompleted || got.CompletedAt == nil {
		t.Errorf("job after submit = %+v", got)
	}
	r, err := s.Result(ctx, j.ID)
	mustNoErr(t, err)
	var decoded map[string]any
	if err := json.Unmarshal(r.Body, &decoded); err != nil || decoded["job_id"] != j.ID {
		t.Errorf("result body = %s (%v)", r.Body, err)
	}
	if string(r.BodySHA256) != string(sub.BodySHA256) || r.CrawlerID != "lab-1" {
		t.Errorf("result = %+v", r)
	}

	// Identical resubmission and a fresh nonce are both replays.
	wantErr(t, s.SubmitResult(ctx, sub), store.ErrReplay)
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-a-000000006", now, true)), store.ErrReplay)
	_, err = s.Result(ctx, unknown.ID)
	wantErr(t, err, store.ErrNotFound)
}

func testSubmitExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	j := addJob(t, s, "lab-1", t0, 5*time.Minute)
	if _, ok, _ := s.NextJob(ctx, "lab-1", t0); !ok {
		t.Fatal("job not delivered")
	}
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-e-000000001", t0.Add(5*time.Minute), true)), store.ErrExpired)
	// A rejected submission must not consume the nonce or complete the job.
	if got, _ := s.Job(ctx, j.ID); got.Status != store.JobDelivered {
		t.Errorf("status = %s", got.Status)
	}
	mustNoErr(t, s.UseNonce(ctx, "lab-1", "nonce-e-000000001", t0))
}

func testSubmitOrdering(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	j := addJob(t, s, "lab-1", t0, 5*time.Minute)
	if _, ok, _ := s.NextJob(ctx, "lab-1", t0); !ok {
		t.Fatal("job not delivered")
	}
	// A nonce already used for a job poll can't be reused for a result.
	mustNoErr(t, s.UseNonce(ctx, "lab-1", "nonce-o-000000001", t0))
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-o-000000001", t0, true)), store.ErrReplay)
	// A tampered (invalid) submission doesn't burn the job.
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-o-000000002", t0, false)), store.ErrUnauthorized)
	mustNoErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-o-000000002", t0, true)))
}

func testAudit(t *testing.T, s store.Store) {
	ctx := context.Background()
	mustNoErr(t, s.Audit(ctx, "admin", "crawler.create", map[string]string{"id": "lab-1"}))
	mustNoErr(t, s.Audit(ctx, "system", "noop", nil))
	list, err := s.ListAudit(ctx, 10)
	mustNoErr(t, err)
	if len(list) != 2 || list[0].Action != "noop" || list[1].Actor != "admin" {
		t.Fatalf("audit = %+v", list)
	}
	var d map[string]string
	if err := json.Unmarshal(list[1].Details, &d); err != nil || d["id"] != "lab-1" {
		t.Errorf("details = %s", list[1].Details)
	}
	if list, _ := s.ListAudit(ctx, 1); len(list) != 1 {
		t.Errorf("limit not applied: %d", len(list))
	}
}
