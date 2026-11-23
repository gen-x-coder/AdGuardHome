package dnsforward

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/AdGuardHome/internal/stats"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testQueryLog is a simple [querylog.QueryLog] implementation for tests.
type testQueryLog struct {
	// QueryLog is embedded here simply to make testQueryLog
	// a [querylog.QueryLog] without actually implementing all methods.
	querylog.QueryLog

	lastParams *querylog.AddParams
}

// Add implements the [querylog.QueryLog] interface for *testQueryLog.
func (l *testQueryLog) Add(p *querylog.AddParams) {
	l.lastParams = p
}

// ShouldLog implements the [querylog.QueryLog] interface for *testQueryLog.
func (l *testQueryLog) ShouldLog(string, uint16, uint16, []string) bool {
	return true
}

// testStats is a simple [stats.Interface] implementation for tests.
type testStats struct {
	// Stats is embedded here simply to make testStats a [stats.Interface]
	// without actually implementing all methods.
	stats.Interface

	lastEntry *stats.Entry
}

// Update implements the [stats.Interface] interface for *testStats.
func (l *testStats) Update(e *stats.Entry) {
	if e.Domain == "" {
		return
	}

	l.lastEntry = e
}

// ShouldCount implements the [stats.Interface] interface for *testStats.
func (l *testStats) ShouldCount(string, uint16, uint16, []string) bool {
	return true
}

func TestServer_ProcessQueryLogsAndStats(t *testing.T) {
	const domain = "example.com."

	testCases := []struct {
		name           string
		domain         string
		proto          proxy.Proto
		addr           netip.AddrPort
		clientID       string
		wantLogProto   querylog.ClientProto
		wantStatClient string
		wantCode       resultCode
		reason         filtering.Reason
		wantStatResult stats.Result
	}{{
		name:           "success_udp",
		domain:         domain,
		proto:          proxy.ProtoUDP,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   "",
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.NotFilteredNotFound,
		wantStatResult: stats.RNotFiltered,
	}, {
		name:           "success_tls_clientid",
		domain:         domain,
		proto:          proxy.ProtoTLS,
		addr:           testClientAddrPort,
		clientID:       "cli42",
		wantLogProto:   querylog.ClientProtoDoT,
		wantStatClient: "cli42",
		wantCode:       resultCodeSuccess,
		reason:         filtering.NotFilteredNotFound,
		wantStatResult: stats.RNotFiltered,
	}, {
		name:           "success_tls",
		domain:         domain,
		proto:          proxy.ProtoTLS,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   querylog.ClientProtoDoT,
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.NotFilteredNotFound,
		wantStatResult: stats.RNotFiltered,
	}, {
		name:           "success_quic",
		domain:         domain,
		proto:          proxy.ProtoQUIC,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   querylog.ClientProtoDoQ,
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.NotFilteredNotFound,
		wantStatResult: stats.RNotFiltered,
	}, {
		name:           "success_https",
		domain:         domain,
		proto:          proxy.ProtoHTTPS,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   querylog.ClientProtoDoH,
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.NotFilteredNotFound,
		wantStatResult: stats.RNotFiltered,
	}, {
		name:           "success_dnscrypt",
		domain:         domain,
		proto:          proxy.ProtoDNSCrypt,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   querylog.ClientProtoDNSCrypt,
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.NotFilteredNotFound,
		wantStatResult: stats.RNotFiltered,
	}, {
		name:           "success_udp_filtered",
		domain:         domain,
		proto:          proxy.ProtoUDP,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   "",
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.FilteredBlockList,
		wantStatResult: stats.RFiltered,
	}, {
		name:           "success_udp_sb",
		domain:         domain,
		proto:          proxy.ProtoUDP,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   "",
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.FilteredSafeBrowsing,
		wantStatResult: stats.RSafeBrowsing,
	}, {
		name:           "success_udp_ss",
		domain:         domain,
		proto:          proxy.ProtoUDP,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   "",
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.FilteredSafeSearch,
		wantStatResult: stats.RSafeSearch,
	}, {
		name:           "success_udp_pc",
		domain:         domain,
		proto:          proxy.ProtoUDP,
		addr:           testClientAddrPort,
		clientID:       "",
		wantLogProto:   "",
		wantStatClient: "1.2.3.4",
		wantCode:       resultCodeSuccess,
		reason:         filtering.FilteredParental,
		wantStatResult: stats.RParental,
	}, {
		name:           "success_udp_pc_empty_fqdn",
		domain:         ".",
		proto:          proxy.ProtoUDP,
		addr:           netip.MustParseAddrPort("4.3.2.1:1234"),
		clientID:       "",
		wantLogProto:   "",
		wantStatClient: "4.3.2.1",
		wantCode:       resultCodeSuccess,
		reason:         filtering.FilteredParental,
		wantStatResult: stats.RParental,
	}}

	ups, err := upstream.AddressToUpstream("1.1.1.1", nil)
	require.NoError(t, err)

	for _, tc := range testCases {
		ql := &testQueryLog{}
		st := &testStats{}
		srv := &Server{
			baseLogger: testLogger,
			logger:     testLogger,
			queryLog:   ql,
			stats:      st,
			anonymizer: aghnet.NewIPMut(nil),
		}
		t.Run(tc.name, func(t *testing.T) {
			req := &dns.Msg{
				Question: []dns.Question{{
					Name: tc.domain,
				}},
			}
			pctx := &proxy.DNSContext{
				Proto:    tc.proto,
				Req:      req,
				Res:      &dns.Msg{},
				Addr:     tc.addr,
				Upstream: ups,
			}
			dctx := &dnsContext{
				proxyCtx:  pctx,
				startTime: time.Now(),
				result: &filtering.Result{
					Reason: tc.reason,
				},
				clientID: tc.clientID,
			}

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			code := srv.processQueryLogsAndStats(ctx, testLogger, dctx)
			assert.Equal(t, tc.wantCode, code)
			assert.Equal(t, tc.wantLogProto, ql.lastParams.ClientProto)
			assert.Equal(t, tc.wantStatClient, st.lastEntry.Client)
			assert.Equal(t, tc.wantStatResult, st.lastEntry.Result)
		})
	}
}

func TestServer_ProcessQueryLogsAndStats_category(t *testing.T) {
	f, err := filtering.New(&filtering.Config{
		Logger:  testLogger,
		DataDir: t.TempDir(),
		Filters: []filtering.FilterYAML{{
			URL:    "https://list1.example/",
			Filter: filtering.Filter{ID: 1},
		}, {
			URL:      "https://list2.example/",
			Category: filtering.CategorySecurity,
			Filter:   filtering.Filter{ID: 2},
		}, {
			URL:      "https://list3.example/",
			Category: filtering.CategoryParental,
			Filter:   filtering.Filter{ID: 3},
		}},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(f.Close)

	testCases := []struct {
		name   string
		reason filtering.Reason
		listID rulelist.APIID
		want   stats.Result
	}{{
		name:   "default_list",
		reason: filtering.FilteredBlockList,
		listID: 1,
		want:   stats.RFiltered,
	}, {
		name:   "security_list",
		reason: filtering.FilteredBlockList,
		listID: 2,
		want:   stats.RSafeBrowsing,
	}, {
		name:   "parental_list",
		reason: filtering.FilteredBlockList,
		listID: 3,
		want:   stats.RParental,
	}, {
		name:   "custom_rules",
		reason: filtering.FilteredBlockList,
		listID: rulelist.APIIDCustom,
		want:   stats.RFiltered,
	}, {
		name:   "blocked_service",
		reason: filtering.FilteredBlockedService,
		listID: 2,
		want:   stats.RFiltered,
	}, {
		name:   "allowlist",
		reason: filtering.NotFilteredAllowList,
		listID: 2,
		want:   stats.RNotFiltered,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			st := &testStats{}
			srv := &Server{
				baseLogger: testLogger,
				logger:     testLogger,
				queryLog:   &testQueryLog{},
				stats:      st,
				anonymizer: aghnet.NewIPMut(nil),
				dnsFilter:  f,
			}

			dctx := &dnsContext{
				proxyCtx: &proxy.DNSContext{
					Proto: proxy.ProtoUDP,
					Req: &dns.Msg{
						Question: []dns.Question{{Name: "example.com."}},
					},
					Res:  &dns.Msg{},
					Addr: testClientAddrPort,
				},
				startTime: time.Now(),
				result: &filtering.Result{
					Reason: tc.reason,
					Rules:  []*filtering.ResultRule{{FilterListID: tc.listID}},
				},
			}

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			code := srv.processQueryLogsAndStats(ctx, testLogger, dctx)
			require.Equal(t, resultCodeSuccess, code)

			assert.Equal(t, tc.want, st.lastEntry.Result)
		})
	}
}
