import { Component } from 'react'

export default class WorkspaceErrorBoundary extends Component {
  state = { failed: false }

  static getDerivedStateFromError() { return { failed: true } }

  render() {
    if (!this.state.failed) return this.props.children
    return <section className="card empty-state" role="alert">
      <h1>This page could not be displayed</h1>
      <p>Your saved assessments are still available. Retry this page or choose another workspace page from the navigation.</p>
      <button type="button" className="btn-primary" onClick={() => this.setState({ failed: false })}>Retry page</button>
    </section>
  }
}
