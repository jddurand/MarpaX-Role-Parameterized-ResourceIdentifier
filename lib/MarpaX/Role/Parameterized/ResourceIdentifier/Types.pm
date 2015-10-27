use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Types;

# ABSTRACT: Type tools for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

use Type::Library
  -base,
  -declare => qw /SchemeLike AbsoluteReference StringifiedAbsoluteReference/;
use Types::Standard -all;
use Type::Utils -all;
use Types::TypeTiny qw/StringLike/;
use Types::Encodings qw/Bytes/;

declare SchemeLike,
  as "Type::Tiny"->new(
                       name       => "SchemeLike",
                       constraint => sub { $_ =~ /^[A-Za-z][A-Za-z0-9+.-]*$/ },
                       message    => sub { "$_ ain't looking like a scheme" },
                      );

declare AbsoluteReference,
  as "Type::Tiny"->new(
                       name       => "AbsoluteReference",
                       constraint => sub { ConsumerOf[__PACKAGE__]->check($_) && $_->is_absolute },
                       message    => sub { "$_ ain't an absolute resource identifier" },
                      );

declare StringifiedAbsoluteReference,
  as "Type::Tiny"->new(
                       name       => "StringifiedAbsoluteReference",
                       constraint => sub { my ($str, $caller) = @_; Str->check($str) && $caller->can('new') && AbsoluteReference->check($caller->new($str)) },
                       message    => sub { "$_ ain't a stringified absolute reference" },
                      );

1;
