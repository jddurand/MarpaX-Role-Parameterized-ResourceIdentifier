use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Types;

# ABSTRACT: Type tools for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

use Type::Library
  -base,
  -declare => qw /Common Generic/;
use Scalar::Util qw/blessed/;
use Types::Standard -all;
use Type::Utils -all;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use Data::Dumper;
our $TO_STRING = sub {
  my @ordered_fields = sort $_[0]->FIELDS;
  Data::Dumper->new([map { $_[0]->$_ } @ordered_fields], \@ordered_fields)
};

our $_data_printer = sub {
  require Data::Printer::Filter;
  require Term::ANSIColor;
  my $self   = shift;

  my @values = map { scalar &Data::Printer::p(\$_) } @$self;
  my $label  = Term::ANSIColor::colored($self->TYPE||'struct', 'bright_yellow');

  if (grep /\n/, map { $_ // ''} @values) {
    return sprintf(
                   "%s[\n\t%s,\n]",
                   $label,
                   join(qq[,\n\t], map { s/\n/\n\t/gm; $_ // ''} map { $_ // '' } @values),
                  );
  }
  sprintf('%s[ %s ]', $label, join q[, ], map { $_ // '' } @values);
};

use MooX::Struct -rw,
  StructCommon => [ output         => [ isa => Str,           default => sub {    '' } ], # Parse tree value
                    scheme         => [ isa => Str|Undef,     default => sub { undef } ],
                    opaque         => [ isa => Str,           default => sub {    '' } ],
                    fragment       => [ isa => Str|Undef,     default => sub { undef } ],
                    TO_STRING      => sub { goto &$TO_STRING },
                    _data_printer  => sub { goto &$_data_printer }
                  ],
  StructGeneric => [ -extends => ['StructCommon'],
                     hier_part     => [ isa => Str|Undef,     default => sub { undef } ],
                     query         => [ isa => Str|Undef,     default => sub { undef } ],
                     segment       => [ isa => Str|Undef,     default => sub { undef } ],
                     authority     => [ isa => Str|Undef,     default => sub { undef } ],
                     path          => [ isa => Str|Undef,     default => sub { undef } ],
                     relative_ref  => [ isa => Str|Undef,     default => sub { undef } ],
                     relative_part => [ isa => Str|Undef,     default => sub { undef } ],
                     userinfo      => [ isa => Str|Undef,     default => sub { undef } ],
                     host          => [ isa => Str|Undef,     default => sub { undef } ],
                     port          => [ isa => Str|Undef,     default => sub { undef } ],
                     ip_literal    => [ isa => Str|Undef,     default => sub { undef } ],
                     ipv4_address  => [ isa => Str|Undef,     default => sub { undef } ],
                     reg_name      => [ isa => Str|Undef,     default => sub { undef } ],
                     ipv6_address  => [ isa => Str|Undef,     default => sub { undef } ],
                     ipv6_addrz    => [ isa => Str|Undef,     default => sub { undef } ],
                     ipvfuture     => [ isa => Str|Undef,     default => sub { undef } ],
                     zoneid        => [ isa => Str|Undef,     default => sub { undef } ],
                     segments      => [ isa => ArrayRef[Str], default => sub {  MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new->uri_compat ? [''] : [] } ],
                     TO_STRING      => sub { goto &$TO_STRING },
                     _data_printer  => sub { goto &$_data_printer }
                   ];

#
# A little bit painful: MooX::Struct thingies are anonymous classes
#
class_type Common, { class => blessed(StructCommon->new) };
class_type Generic, { class => blessed(StructGeneric->new) };

1;
