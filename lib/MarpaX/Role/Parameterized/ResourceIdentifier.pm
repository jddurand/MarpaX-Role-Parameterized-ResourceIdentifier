use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier;

# ABSTRACT: MarpaX Parameterized Role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

#
# This is a parameterized role because RFC3986 and RFC3987 share exactly the same
# implementation. The only difference is the grammar. This role will take a grammar
# as target package and generate the action, the internal structure and the required
# methods.
#

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Data::Dumper;
use Encode 2.21 qw/find_encoding/; # 2.21 for mime_name support
require UNIVERSAL::DOES unless defined &UNIVERSAL::DOES;
use Scalar::Does;
use Scalar::Util qw/blessed/;
use Marpa::R2;
use MarpaX::RFC::RFC3629;
use MarpaX::Role::Parameterized::ResourceIdentifier::Grammars;
use MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace;
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::BNF;
use MarpaX::Role::Parameterized::ResourceIdentifier::BUILDARGS;
use Module::Runtime qw/use_module/;
use Moo::Role;
use MooX::HandlesVia;
use MooX::Role::Logger;
use Types::Standard -all;
use Types::Encodings qw/Bytes/;
use Try::Tiny;
use Role::Tiny;
use Unicode::Normalize qw/normalize/;
use constant {
  BNF_ROLE => 'MarpaX::Role::Parameterized::ResourceIdentifier::BNF',
  BUILDARGS_ROLE => 'MarpaX::Role::Parameterized::ResourceIdentifier::BUILDARGS',
  LOGGER_ROLE => 'MooX::Role::Logger',
};
use constant {
  RAW                         => 0,
  DECODED                     => 1,
  #
  # For comparison ladder
  #
  CASE_NORMALIZED             => 2,
  CHARACTER_NORMALIZED        => 3,
  PERCENT_ENCODING_NORMALIZED => 4,
  PATH_SEGMENT_NORMALIZED     => 5,
  SCHEME_BASED_NORMALIZED     => 6,
  _COUNT                      => 7
};
our $indice_normalizer_start = CASE_NORMALIZED;
our $indice_normalizer_end   = SCHEME_BASED_NORMALIZED;

our $setup    = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->instance;
our $grammars = MarpaX::Role::Parameterized::ResourceIdentifier::Grammars->instance;

has _encoding               => ( is => 'ro',  isa => Str, predicate => 1, trigger => 1);
has is_character_normalized => ( is => 'rwp', isa => Bool, default => sub { !!1 } );
has input                   => ( is => 'rwp', isa => Str, trigger => 1);
has _structs                => ( is => 'rw',  isa => ArrayRef[Object] );
our @normalizer_name = qw/case_normalizer
                          character_normalizer
                          percent_encoding_normalizer
                          path_segment_normalizer
                          scheme_based_normalizer/;

foreach (@normalizer_name) {
  has $_ => ( is => 'ro', isa => HashRef[CodeRef], lazy => 1, builder => "build_$_",
              handles_via => 'Hash',
              handles => {
                          "exists_$_"  => 'exists',
                          "get_$_"     => 'get'
                         }
            )
}

sub output { $_[0]->_structs->[_COUNT-1]->_output }

our @ucs_mime_name = map { find_encoding($_)->mime_name } qw/UTF-8 UTF-16 UTF-16BE UTF-16LE UTF-32 UTF-32BE UTF-32LE/;

sub _trigger__encoding {
  my ($self, $_encoding) = @_;
  #
  # Remember if the octets were in an UCS-based encoding
  #
  my $enc_mime_name = find_encoding($_encoding)->mime_name;
  $self->_set__is_character_normalized(grep { $enc_mime_name eq $_ } @ucs_mime_name);
}

use MooX::Role::Parameterized;
use MooX::Struct -rw,
  Common => [ output         => [ isa => Str,           default => sub {    '' } ], # Parse tree value
              scheme         => [ isa => Str|Undef,     default => sub { undef } ],
              opaque         => [ isa => Str,           default => sub {    '' } ],
              fragment       => [ isa => Str|Undef,     default => sub { undef } ],
            ],
  Generic => [ -extends => ['Common'],
               hier_part     => [ isa => Str|Undef,     default => sub { undef } ],
               query         => [ isa => Str|Undef,     default => sub { undef } ],
               segment       => [ isa => Str|Undef,     default => sub { undef } ],
               authority     => [ isa => Str|Undef,     default => sub { undef } ],
               path          => [ isa => Str|Undef,     default => sub { undef } ],
               path_abempty  => [ isa => Str|Undef,     default => sub { undef } ],
               path_absolute => [ isa => Str|Undef,     default => sub { undef } ],
               path_noscheme => [ isa => Str|Undef,     default => sub { undef } ],
               path_rootless => [ isa => Str|Undef,     default => sub { undef } ],
               path_empty    => [ isa => Str|Undef,     default => sub { undef } ],
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
               segments      => [ isa => ArrayRef[Str], default => sub {  $setup->uri_compat ? [''] : [] } ],
             ];

role {
  my $params = shift;

  # -----------------------
  # Sanity checks on params
  # -----------------------
  my %PARAMS = ();
  map { $PARAMS{$_} = $params->{$_} } qw/whoami type bnf_package/;
  #
  # We will not insert methods in the role but in the calling package
  #
  croak 'whoami must exist and do Str' unless Str->check($PARAMS{whoami});
  my $whoami = $PARAMS{whoami};
  #
  # And this depend on its type: Common or Generic
  #
  croak 'type must exist and do Enum[qw/Common Generic/]' unless defined($PARAMS{type}) && grep {$_ eq $PARAMS{type}} qw/Common Generic/;
  my $type = $PARAMS{type};
  my $is_Common = $type eq 'Common';
  #
  # There are only two things that differ between URI and IRI:
  # - the grammar
  # - the normalizers
  #
  croak "[$type] bnf_package must exist and do Str" unless Str->check($PARAMS{bnf_package});
  my $bnf_package = $PARAMS{bnf_package};
  use_module($bnf_package);
  #
  # Eventual extends should be done asap
  #
  if (exists($params->{extends})) {
    croak "[$type] extends must do ArrayRef" unless ArrayRef->check($params->{extends});
    my $extends_sub;
    croak "[$type] $whoami must can extends (did you forgot to use Moo ?)" unless $extends_sub = $whoami->can('extends');
    &$extends_sub(@{$params->{extends}});
    #"Moo"->_set_superclasses($klass, @parents);
    #"Moo"->_maybe_reset_handlemoose($klass);
    # extends(@{$params->{extends}});
  }
  #
  # ----------------------------
  # Sanity checks on bnf_package
  # ----------------------------
  my $bnf_instance = $bnf_package->new();
  Role::Tiny->apply_roles_to_object($bnf_instance, BNF_ROLE) unless does($bnf_instance, BNF_ROLE);
  #
  # Make sure bnf instance really return what we want
  #
  my %BNF = ();
  map { $BNF{$_} = $bnf_instance->$_} qw/grammar bnf reserved unreserved pct_encoded is_utf8 mapping action_name/;
  croak "[$type] $bnf_package->grammar must do InstanceOf['Marpa::R2::Scanless::G']"  unless blessed($BNF{grammar}) && blessed($BNF{grammar}) eq 'Marpa::R2::Scanless::G';
  croak "[$type] $bnf_package->bnf must do Str"                    unless Str->check($BNF{bnf});
  croak "[$type] $bnf_package->reserved must do RegexpRef"         unless RegexpRef->check($BNF{reserved});
  croak "[$type] $bnf_package->unreserved must do RegexpRef"       unless RegexpRef->check($BNF{unreserved});
  croak "[$type] $bnf_package->pct_encoded must do Str|Undef"      unless Str->check($BNF{pct_encoded}) || Undef->check($BNF{pct_encoded});
  croak "[$type] $bnf_package->is_utf8 must do Bool"               unless Bool->check($BNF{is_utf8});
  croak "[$type] $bnf_package->mapping must do Hashref[Str]"       unless HashRef->check($BNF{mapping}) && ! grep { ! Str->check($_) } keys %{$BNF{mapping}};
  croak "[$type] $bnf_package->pct_encoded must be like <...>'"    unless (! defined($BNF{pct_encoded})) || $BNF{pct_encoded} =~ /^<.*>$/;
  #
  # If reserved is a RegexpRef, then unreserved must be a RegexpRef
  #
  if (RegexpRef->check($BNF{reserved})) {
    croak "[$type] $bnf_package->unreserved must do RegexpRef when $bnf_package->reserved does RegexpRef" unless RegexpRef->check($BNF{unreserved});
  }
  #
  # A bnf package must provide correspondance between grammar symbols and the fields in the structure
  # A field can appear more than once as a value, but its semantic is fixed by us.
  # A symbol must be like <...>
  #
  my %fields = ();
  my @fields = $is_Common ? Common->FIELDS : Generic->FIELDS;
  map { $fields{$_} = 0 } @fields;
  foreach (keys %{$BNF{mapping}}) {
    my $field = $BNF{mapping}->{$_};
    croak "[$type] mapping $_ must be like <...>" unless $_ =~ /^<.*>$/;
    croak "[$type] mapping of $_ is unknown field: $field" unless exists $fields{$field};
    $fields{$field}++;
  }
  my @not_found = grep { ! $fields{$_} } keys %fields;
  croak "[$type] Unmapped fields: @not_found" unless ! @not_found;

  my $reserved    = $BNF{reserved};              # can be undef
  my $unreserved  = $BNF{unreserved};            # can be undef
  my $pct_encoded = $BNF{pct_encoded} // '';
  my $is_utf8     = $BNF{is_utf8};
  my $action_name = $BNF{action_name};

  my $marpa_trace_terminals = $setup->marpa_trace_terminals;
  my $marpa_trace_values    = $setup->marpa_trace_values;
  my $marpa_trace           = $setup->marpa_trace;
  my $with_logger           = $setup->with_logger;
  my $uri_compat            = $setup->uri_compat;
  #
  # -------
  # Logging
  # -------
  #
  # In any case, we want Marpa to be "silent", unless explicitely traced
  #
  my $trace;
  open(my $trace_file_handle, ">", \$trace) || croak "[$type] Cannot open trace filehandle, $!";
  if ($marpa_trace) {
    local $MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace::bnf_package = $bnf_package;
    tie ${$trace_file_handle}, 'MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace';
  }
  # -----
  # Roles
  # -----
  BUILDARGS_ROLE->apply({whoami => $whoami, type => 'NotTop', second_argument => 'base'}, target=> $whoami);
  Role::Tiny->apply_roles_to_package($whoami, LOGGER_ROLE) unless $whoami->DOES(LOGGER_ROLE);
  #
  # -------------------------------------
  # Helpers used internally, not exported
  # -------------------------------------
  my $_indice_description = sub {
    # my ($self, $indice) = @_;
    return 'Invalid indice' if ! defined($_[1]);
    if    ($_[1] == RAW                        ) { return 'Raw value                        ' }
    elsif ($_[1] == DECODED                    ) { return 'Decoded raw value                ' }
    elsif ($_[1] == CASE_NORMALIZED            ) { return 'Case normalized value            ' }
    elsif ($_[1] == CHARACTER_NORMALIZED       ) { return 'Character normalized value       ' }
    elsif ($_[1] == PERCENT_ENCODING_NORMALIZED) { return 'Percent encoding mormalized value' }
    elsif ($_[1] == PATH_SEGMENT_NORMALIZED    ) { return 'Path segment normalized value    ' }
    elsif ($_[1] == SCHEME_BASED_NORMALIZED    ) { return 'Scheme based normalized value    ' }
    else                                         { return 'Unknown indice                   ' }
  };
  my $max = _COUNT - 1;
  # -------------
  # Inlined stubs
  # -------------
  #
  # Normalizers
  #
  my @normalizer_sub = ();
  foreach (0..$max) {
    if (($_ < $indice_normalizer_start) || ($_ > $indice_normalizer_end)) {
      push(@normalizer_sub, undef) # No normalizer at this indice
    } else {
      my $inormalizer = $_ - $indice_normalizer_start;
      my $builder = "build_$normalizer_name[$inormalizer]";
      my $exists = "exists_$normalizer_name[$inormalizer]";
      my $get = "get_$normalizer_name[$inormalizer]";
      push(@normalizer_sub, sub {
             my ($self, $field, $value, $lhs) = @_;
             my $criteria = $field || $lhs || '';
             $self->$exists($criteria) ? $self->$get($criteria)->($self, $field, $value, $lhs) : $value
           }
          );
    }
  }
  #
  # Marpa inner action
  #
  my %MAPPING = %{$BNF{mapping}};
  my $args2array_sub = sub {
    my ($self, $lhs, $field, @args) = @_;
    my $rc = [ ('') x _COUNT ];
    #
    # Concatenate (not a reference == lexeme)
    #
    foreach my $irc (0..$max) {
      do { $rc->[$irc] .= ref($args[$_]) ? $args[$_]->[$irc] : $args[$_] } for (0..$#args)
    }
    #
    # Decoded output is explicitely done here on the raw output
    #
    if ($lhs eq $pct_encoded) {
      my $octets = '';
      while ($rc->[DECODED] =~ m/(?<=%)[^%]+/gp) {
        $octets .= chr(hex(${^MATCH}))
      }
      $rc->[DECODED] = MarpaX::RFC::RFC3629->new($octets)->output;
    }

    #
    # The normalization ladder
    #
    foreach my $inormalizer ($indice_normalizer_start..$indice_normalizer_end) {
      #
      # For each normalized value, we apply the previous normalizers in order
      #
      do { $rc->[$inormalizer] = $normalizer_sub[$_]->($self, $field, $rc->[$inormalizer], $lhs) } for ($indice_normalizer_start..$inormalizer);
    }
    $rc
  };
  #
  # Input trigger
  #
  my %recognizer_option = (
                           trace_terminals =>  $marpa_trace_terminals,
                           trace_values =>  $marpa_trace_values,
                           ranking_method => 'high_rule_only',
                           grammar => $BNF{grammar}
                          );
  my $trigger_input = sub {
    my ($self, $input) = @_;

    my $r = Marpa::R2::Scanless::R->new(\%recognizer_option);
    $r->read(\$input);
    croak "[$type] Parse of the input is ambiguous" if $r->ambiguous;
    $self->_structs([map { $is_Common ? Common->new : Generic->new } (0..$max)]);
    $r->value($self);
    if ($with_logger) {
      foreach (0..$max) {
        my $d = Data::Dumper->new([$self->_structs->[$_]->output], [$self->$_indice_description($_)]);
        $self->_logger->debugf('%s: %s', $bnf_package, $d->Dump);
      }
    }
  };
  #
  # ----------
  # Injections
  # ----------
  #
  if ($type eq 'Common') {
    install_modifier($whoami, 'fresh',  grammar => sub { $BNF{grammar} });
    install_modifier($whoami, 'fresh',  bnf => sub { $BNF{bnf} });
    install_modifier($whoami, 'fresh',  unreserved => sub { $BNF{unreserved} });
    install_modifier($whoami, 'fresh', _trigger_input => $trigger_input);
  } else {
    install_modifier($whoami, 'around',  grammar => sub { $BNF{grammar} });
    install_modifier($whoami, 'around',  bnf => sub { $BNF{bnf} });
    install_modifier($whoami, 'around',  unreserved => sub { $BNF{unreserved} });
    install_modifier($whoami, 'around', _trigger_input => sub {
                       my ($orig, $self, $input) = @_;
                       try {
                         $self->$trigger_input($input);
                       } catch {
                         if ($setup->uri_compat) {
                           if ($setup->with_logger) {
                             foreach (split(/\n/, "$_")) {
                               $self->_logger->tracef('%s: %s', $bnf_package, $_);
                             }
                           }
                           $self->$orig($input);
                         } else {
                           croak $_;
                         }
                       }
                     }
                    );
  }
  #
  # This is installed in the BNF package, so there should never be a conflict
  #
  install_modifier($bnf_package, 'fresh', $action_name => sub {
                     my ($self, @args) = @_;
                     my $slg         = $Marpa::R2::Context::slg;
                     my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
                     $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
                     my $field = $MAPPING{$lhs};
                     my $array_ref = &$args2array_sub($self, $lhs, $field, @args);
                     if ($with_logger) {
                       $self->_logger->tracef('%s: %s ::= %s', $bnf_package, $lhs, "@rhs");
                       $self->_logger->tracef('%s:   IN  %s', $bnf_package, \@args);
                       $self->_logger->tracef('%s:   OUT %s', $bnf_package, $array_ref);
                     }
                     my $structs = $self->_structs;
                     if (defined($field)) {
                       #
                       # Segments is special
                       #
                       if ($field eq 'segments') {
                         push(@{$structs->[$_]->segments}, $array_ref->[$_]) for (0..$max);
                       } else {
                         $structs->[$_]->$field($array_ref->[$_]) for (0..$max);
                       }
                     }
                     $array_ref
                   }
                  );
  #
  # For every structure field, we inject a method with an underscore in it
  # Optional indice is which version we want, defaulting to DECODED
  #
  foreach (@fields) {
    my $field = $_;
    my $name = "_$field";
      install_modifier($whoami,
                       $whoami->can($name) ? 'around' : 'fresh',
                       $name =>  sub { $_[1] //= DECODED, $_[0]->_structs->[$_[1]]->$field }
                      );
  }
};
#
# Class methods common to any Resource Identifier
#
sub percent_encode {
  my ($class, $string, $regexp) = @_;

  my $encoded = $string;
  $encoded =~ s!$regexp!
    {
     #
     # ${^MATCH} is a read-only variable
     # and Encode::encode is affecting $match -;
     #
     my $match = ${^MATCH};
     join('', map { '%' . uc(unpack('H2', $_)) } split(//, Encode::encode('UTF-8', $match, Encode::FB_CROAK)))
    }
    !egp;
  $encoded
}

sub remove_dot_segments {
  my ($self, $input) = @_;

  #
  # 1.  The input buffer is initialized with the now-appended path
  # components and the output buffer is initialized to the empty
  # string.
  #
  my $output = '';

  # my $i = 0;
  # my $step = ++$i;
  # my $substep = '';
  # printf STDERR "%-10s %-30s %-30s\n", "STEP", "OUTPUT BUFFER", "INPUT BUFFER";
  # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
  # $step = ++$i;
  #
  # 2.  While the input buffer is not empty, loop as follows:
  #
  while (length($input)) {
    #
    # A. If the input buffer begins with a prefix of "../" or "./",
    #    then remove that prefix from the input buffer; otherwise,
    #
    if (index($input, '../') == 0) {
      substr($input, 0, 3, '');
      # $substep = 'A';
    }
    elsif (index($input, './') == 0) {
      substr($input, 0, 2, '');
      # $substep = 'A';
    }
    #
    # B. if the input buffer begins with a prefix of "/./" or "/.",
    #    where "." is a complete path segment, then replace that
    #    prefix with "/" in the input buffer; otherwise,
    #
    elsif (index($input, '/./') == 0) {
      substr($input, 0, 3, '/');
      # $substep = 'B';
    }
    elsif ($input =~ /^\/\.(?:[\/]|\z)/) {            # Take care this can confuse the other test on '/../ or '/..'
      substr($input, 0, 2, '/');
      # $substep = 'B';
    }
    #
    # C. if the input buffer begins with a prefix of "/../" or "/..",
    #    where ".." is a complete path segment, then replace that
    #    prefix with "/" in the input buffer and remove the last
    #    segment and its preceding "/" (if any) from the output
    #    buffer; otherwise,
    #
    elsif (index($input, '/../') == 0) {
      substr($input, 0, 4, '/');
      $output =~ s/\/?[^\/]*\z//;
      # $substep = 'C';
    }
    elsif ($input =~ /^\/\.\.(?:[^\/]|\z)/) {
      substr($input, 0, 3, '/');
      $output =~ s/\/?[^\/]*\z//;
      # $substep = 'C';
    }
    #
    # D. if the input buffer consists only of "." or "..", then remove
    #    that from the input buffer; otherwise,
    #
    elsif (($input eq '.') || ($input eq '..')) {
      $input = '';
      # $substep = 'D';
    }
    #
    # E. move the first path segment in the input buffer to the end of
    #    the output buffer, including the initial "/" character (if
    #    any) and any subsequent characters up to, but not including,
    #    the next "/" character or the end of the input buffer.
    #
    #    Note: "or the end of the input buffer" ?
    #
    else {
      $input =~ /^\/?([^\/]*)/;                            # This will always match
      $output .= substr($input, $-[0], $+[0] - $-[0], ''); # Note that perl has no problem saying length is zero
      # $substep = 'E';
    }
    # printf STDERR "%-10s %-30s %-30s\n", "$step$substep", $output, $input;
  }
  #
  # 3. Finally, the output buffer is returned as the result of
  #    remove_dot_segments.
  #
  return $output;
}

1;

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut

__DATA__
  if (Undef->check($reserved)) {
    #
    # No escape/unescape in output - at the most we decode the input
    #
    $args2array_sub = sub {
      my ($self, $lhs, $field, @args) = @_;
      my $rc = [ ('') x _COUNT ];

      foreach (@args) {
        if (! ref) { # I could have said ArrayRef->check($_)
          #
          # This is a lexeme
          #
          $rc->[RAW] .= $_, $rc->[NORMALIZED_RAW] .= $_;
          #
          # Eventually unescape what is in the %HH format
          #
          if ($lhs eq $pct_encoded) {
            my $octets = '';
            while (m/(?<=%)[^%]+/gp) { $octets .= chr(hex(${^MATCH})) }
            $_ = $is_utf8 ? MarpaX::RFC::RFC3629->new($octets)->output : $octets
          }
          $rc->[UNESCAPED] .= $_, $rc->[NORMALIZED_UNESCAPED] .= $_,
          $rc->[ESCAPED]   .= $_, $rc->[NORMALIZED_ESCAPED]   .= $_
        } else {
          #
          # This has already been transformed in the previous step
          #
          $rc->[RAW]       .= $_->[RAW],       $rc->[NORMALIZED_RAW]       .= $_->[NORMALIZED_RAW],
          $rc->[UNESCAPED] .= $_->[UNESCAPED], $rc->[NORMALIZED_UNESCAPED] .= $_->[NORMALIZED_UNESCAPED],
          $rc->[ESCAPED]   .= $_->[ESCAPED],   $rc->[NORMALIZED_ESCAPED]   .= $_->[NORMALIZED_ESCAPED]
        }
      }
      #
      # Apply validation on the unescaped value, normalization on all others
      #
      $rc->[NORMALIZED_RAW]       = $self->$normalizer($field, $rc->[NORMALIZED_RAW], $lhs),
      $rc->[NORMALIZED_ESCAPED]   = $self->$normalizer($field, $rc->[NORMALIZED_ESCAPED], $lhs),
      $rc->[NORMALIZED_UNESCAPED] = $self->$normalizer($field, $rc->[NORMALIZED_UNESCAPED], $lhs),
      $rc
    }
  } else {
    $args2array_sub = sub {
      my ($self, $lhs, $field, @args) = @_;
      my $rc = [ ('') x _COUNT ];

      foreach (@args) {
        if (! ref) { # I could have said ArrayRef->check($_)
          #
          # This is a lexeme
          #
          $rc->[RAW] .= $_, $rc->[NORMALIZED_RAW] .= $_;
          if ($_ =~ $reserved) {
            #
            # If this matches the reserved character set: keep it
            #
            $rc->[UNESCAPED] .= $_, $rc->[NORMALIZED_UNESCAPED] .= $_,
            $rc->[ESCAPED]   .= $_, $rc->[NORMALIZED_ESCAPED]   .= $_
          } else {
            #
            # Otherwise eventually unescape what is in the %HH format
            #
            if ($lhs eq $pct_encoded) {
              my $octets = '';
              while (m/(?<=%)[^%]+/gp) { $octets .= chr(hex(${^MATCH})) }
              $_ = $is_utf8 ? MarpaX::RFC::RFC3629->new($octets)->output : $octets
            }
            my ($unescaped, $escaped) = ($_, '');
            #
            # And escape everything that is not an unreserved character
            #
            foreach (split(//, $_)) {
              if ($_ =~ $unreserved) {
                $escaped .= $_
              } else {
                $escaped .= do {
                  #
                  # Because Encode::encode does not like read-only values
                  #
                  my $character = $_;
                  join('', map { '%' . uc(unpack('H2', $_)) } split(//, Encode::encode('UTF-8', $character, Encode::FB_CROAK)))
                }
              }
            }
            $rc->[UNESCAPED] .= $unescaped, $rc->[NORMALIZED_UNESCAPED] .= $unescaped,
            $rc->[ESCAPED]   .= $escaped,   $rc->[NORMALIZED_ESCAPED]   .= $escaped
          }
        } else {
          #
          # This has already been transformed in the previous step
          #
          $rc->[RAW]       .= $_->[RAW],       $rc->[NORMALIZED_RAW]       .= $_->[NORMALIZED_RAW],
          $rc->[UNESCAPED] .= $_->[UNESCAPED], $rc->[NORMALIZED_UNESCAPED] .= $_->[NORMALIZED_UNESCAPED],
          $rc->[ESCAPED]   .= $_->[ESCAPED],   $rc->[NORMALIZED_ESCAPED]   .= $_->[NORMALIZED_ESCAPED]
        }
      }
      #
      # Apply validation on the unescaped value, normalization on all others
      #
      $rc->[NORMALIZED_RAW]       = $self->$normalizer($field, $rc->[NORMALIZED_RAW], $lhs),
      $rc->[NORMALIZED_ESCAPED]   = $self->$normalizer($field, $rc->[NORMALIZED_ESCAPED], $lhs),
      $rc->[NORMALIZED_UNESCAPED] = $self->$normalizer($field, $rc->[NORMALIZED_UNESCAPED], $lhs),
      $rc
    }
  }
  #
  # Generate default action
  #
  my $default_action_sub;
