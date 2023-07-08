package nsid

import (
	"reflect"
	"testing"
)

func TestNewNSID(t *testing.T) {
	type args struct {
		nsidStr string
	}

	tests := []struct {
		name    string
		args    args
		want    *NSID
		wantErr bool
	}{
		{
			name: "successfull case - normal 1",
			args: args{
				nsidStr: "com.example.fooBar",
			},
			want: &NSID{
				dsegments: []string{"com", "example"},
				name:      "fooBar",
				fragment:  "",
				glob:      false,
			},
			wantErr: false,
		},
		{
			name: "successfull case - normal 2",
			args: args{
				nsidStr: "net.users.bob.ping",
			},
			want: &NSID{
				dsegments: []string{"net", "users", "bob"},
				name:      "ping",
				fragment:  "",
				glob:      false,
			},
			wantErr: false,
		},
		{
			name: "successfull case - normal 3",
			args: args{
				nsidStr: "a-0.b-1.c",
			},
			want: &NSID{
				dsegments: []string{"a-0", "b-1"},
				name:      "c",
				fragment:  "",
				glob:      false,
			},
			wantErr: false,
		},
		{
			name: "successfull case - normal 4",
			args: args{
				nsidStr: "a.b.c",
			},
			want: &NSID{
				dsegments: []string{"a", "b"},
				name:      "c",
				fragment:  "",
				glob:      false,
			},
			wantErr: false,
		},
		{
			name: "successfull case - with fragment 1",
			args: args{
				nsidStr: "com.example.fooBar#baz",
			},
			want: &NSID{
				dsegments: []string{"com", "example"},
				name:      "fooBar",
				fragment:  "baz",
				glob:      false,
			},
			wantErr: false,
		},
		{
			name: "successfull case - with fragment 2",
			args: args{
				nsidStr: "net.users.bob.ping#pong",
			},
			want: &NSID{
				dsegments: []string{"net", "users", "bob"},
				name:      "ping",
				fragment:  "pong",
				glob:      false,
			},
			wantErr: false,
		},
		{
			name: "successfull case - with fragment 3",
			args: args{
				nsidStr: "a-0.b-1.c#d",
			},
			want: &NSID{
				dsegments: []string{"a-0", "b-1"},
				name:      "c",
				fragment:  "d",
				glob:      false,
			},
			wantErr: false,
		},
		{
			name: "successfull case - with fragment 4",
			args: args{
				nsidStr: "a.b.c#d",
			},
			want: &NSID{
				dsegments: []string{"a", "b"},
				name:      "c",
				fragment:  "d",
				glob:      false,
			},
			wantErr: false,
		},
		{
			name: "successfull case - with wildcard 1",
			args: args{
				nsidStr: "com.example.*",
			},
			want: &NSID{
				dsegments: []string{"com", "example"},
				name:      "*",
				fragment:  "",
				glob:      true,
			},
			wantErr: false,
		},
		{
			name: "successfull case - with wildcard 2",
			args: args{
				nsidStr: "net.users.bob.*",
			},
			want: &NSID{
				dsegments: []string{"net", "users", "bob"},
				name:      "*",
				fragment:  "",
				glob:      true,
			},
			wantErr: false,
		},
		{
			name: "successfull case - with wildcard 3",
			args: args{
				nsidStr: "a-0.b-1.*",
			},
			want: &NSID{
				dsegments: []string{"a-0", "b-1"},
				name:      "*",
				fragment:  "",
				glob:      true,
			},
			wantErr: false,
		},
		{
			name: "successfull case - with wildcard 4",
			args: args{
				nsidStr: "a.b.*",
			},
			want: &NSID{
				dsegments: []string{"a", "b"},
				name:      "*",
				fragment:  "",
				glob:      true,
			},
			wantErr: false,
		},
		{
			name: "failure case - empty string",
			args: args{
				nsidStr: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - only dot",
			args: args{
				nsidStr: ".",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - not ascii string",
			args: args{
				nsidStr: "com.example.日本語",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - invalid fragment 1",
			args: args{
				nsidStr: "com.example.fooBar#",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - invalid fragment 2",
			args: args{
				nsidStr: "com.example.fooBar#baz#",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - invalid fragment 3",
			args: args{
				nsidStr: "com.example.fooBar#baz#qux",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - too much length",
			args: args{
				nsidStr: "com.example.foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred.plugh.xyzzy.thud.abc.defghi.jklmnop.qrstuv.wxyz.aabbcc.ddeeff.gghhii.jjkkll.mmnnoo.ppqqr.ssttuu.vvwwxx.yyzz.foo.bar.baz.qux.quux.corge.grault.garply.waldo.fred.plugh.xyzzy.thud.abc.defghi.jklmnop.qrstuv.wxyz.aabbcc.ddeeff.gghhii.jjkkll.mmnnoo.ppqqr.ssttuu.vvwwxx.yyzz",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - too few length",
			args: args{
				nsidStr: "com.example",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - invalid wildcard",
			args: args{
				nsidStr: "com.example.*.foo",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failure case - wildcard and fragment",
			args: args{
				nsidStr: "com.example.*#foo",
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewNSID(tt.args.nsidStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewNSID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewNSID() = %v, want %v", got, tt.want)
			}
		})
	}
}
