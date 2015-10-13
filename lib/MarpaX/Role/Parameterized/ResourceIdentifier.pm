use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier;
use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Import::Into;
use Scalar::Does;
use Scalar::Util qw/blessed/;
use Marpa::R2;
use Moo::Role;
use MooX::Role::Parameterized;
use Types::Standard -all;
use Type::Params qw/compile/;

# ABSTRACT: MarpaX Parameterized Role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORTIY

# AUTHORITY

#
# URI/IRI are sharing EXACTLY the same implementation algorithm, only some names are changing.
#
# This is why they consume this parameterized role.
#
role {
  my $params = shift;

  #
  # Sanity check
  # ------------
  foreach (qw/BNF_package start package/) {
    croak "$_ must exist and do Str" unless exists($params->{$_}) && Str->check($params->{$_});
  }

  my $BNF_package = $params->{BNF_package};
  my $start       = $params->{start};
  my $package     = $params->{package};

  my $BNF = $BNF_package->new;

  my $bnf = $BNF->bnf;
  croak "$BNF->bnf must do Str" unless Str->check($bnf);
  croak "$BNF->bnf cannot have 'inaccessible is' (even if commented)" if ($bnf =~ /\binaccessible\s+is\b/);
  croak "$BNF->bnf cannot have 'action =>' (even if commented)" if ($bnf =~ /\baction\s+=>/);

  my $escape   = $BNF->escape;
  croak "$BNF->escape $escape must do CodeRef" unless CodeRef->check($escape);

  my $unescape = $BNF->unescape;
  croak "$BNF->unescape must do CodeRef" unless CodeRef->check($unescape);

  $start = "<$start>" if substr($start, 0, 1) ne '<';

  my %G1 = ();
  if (exists($params->{G1})) {
    croak 'G1 reference type must be HASH' unless does $params->{G1}, 'HASH';
    foreach (keys %{$params->{G1}}) {
      # Every key must start with '<'
      croak "G1 $_ must be in the form <...>" unless substr($_, 0, 1) eq '<';
      # Every value must do CODE
      croak "G1 $_ value must do CODE" unless does $params->{G1}->{$_}, 'CODE';
      # It is illegal to provide a value for the start symbol: we want it to return its $self
      croak "G1 $_ value is illegal for the start rule" if ($_ eq $start);
    }
    %G1 = %{$params->{G1}};
  }
  #
  # Good, we can generate code and produce grammar singletons
  # ---------------------------------------------------------
  #
  # The BNF and the grammar that will look like a singleton
  #
  $bnf = "inaccessible is ok by default\n:start ::= $start\n:default ::= action => ${package}::__action\n$bnf";
  my $trace;
  open(my $trace_file_handle, ">", \$trace) || croak "Cannot open trace filehandle, $!";
  my $GRAMMAR = Marpa::R2::Scanless::G->new({%{$BNF->grammar_option}, source => \$bnf, trace_file_handle => $trace_file_handle});
  #
  # Inject methods
  #
  install_modifier($package, $package->can('bnf')     ? 'around' : 'fresh', 'bnf',
                   sub { $bnf } );
  install_modifier($package, $package->can('grammar') ? 'around' : 'fresh', 'grammar',
                   sub { $GRAMMAR } );
  install_modifier($package, $package->can('escape')   ? 'around' : 'fresh', 'escape',
                   sub { goto &$escape } );
  install_modifier($package, $package->can('unescape') ? 'around' : 'fresh', 'unescape',
                   sub { goto &$unescape } );
  install_modifier($package, $package->can('__action') ? 'around' : 'fresh', '__action',
                   sub {
                     my ($self, @args) = @_;
                     #
                     # We always propate only the concatenation, even if the scheme-specific rules
                     # except at the very end, where the final parse value is $self, i.e.
                     # a structure instance -;
                     #
                     my $rc = join('', @args);
                     #
                     # Specific sub-actions
                     #
                     my $slg         = $Marpa::R2::Context::slg;
                     my ($lhs, @rhs) = map { $slg->symbol_display_form($_) } $slg->rule_expand($Marpa::R2::Context::rule);
                     #
                     # For simple symbols, symbol_display_form() removes the <>. Note that we enforced it upper, so we
                     # are safe to enforce it here, eventually.
                     #
                     $lhs = "<$lhs>" if (substr($lhs, 0, 1) ne '<');
                     exists $G1{$lhs} ? do { $G1{$lhs}->($self, $rc) } : ($lhs eq $start) ? $self : $rc;
                   }
                  );
};

1;

=head1 SEE ALSO

L<Uniform Resource Identifier (URI): Generic Syntax|http://tools.ietf.org/html/rfc3986>

L<Internationalized Resource Identifier (IRI): Generic Syntax|http://tools.ietf.org/html/rfc3987>

L<Formats for IPv6 Scope Zone Identifiers in Literal Address Formats|https://tools.ietf.org/html/draft-fenner-literal-zone-02>

=cut
